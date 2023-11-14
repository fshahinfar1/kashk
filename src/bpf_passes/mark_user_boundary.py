from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from prune import READ_PACKET, WRITE_PACKET
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from passes.clone import clone_pass


MODULE_TAG = '[Mark Boundary]'
FAILED = 999
PARENT_INST = 1000

current_function = None
cb_ref = None
fail_ref = None
failure_path_id = 1

NO = 0
YES = 1
MARKED = 2


def get_number_of_failure_paths():
    # Number of failure paths that we have already found
    return failure_path_id - 1


@contextmanager
def remember_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield None
    finally:
        current_function = tmp


def _check_if_known_func_condition_is_met(inst, info):
    if inst.name == 'malloc':
        arg = inst.args[0]
        return arg.kind == clang.CursorKind.INTEGER_LITERAL
    return True


_have_processed = None
def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        func = inst.get_function_def()
        assert func is not None or inst.is_func_ptr, 'only function pointer are allowed to not have function structure'
        if func is None:
            # TODO: calling function pointers are not support for now. But I should add the support
            # debug(MODULE_TAG, 'calling function pointers are not support for now')
            return inst, YES
        assert func.may_fail or func.may_succeed, f'The information about function failures should be processed before this step (func: {func.name})'

        if func.is_empty():
            if func.may_succeed:
                # This is the case of KNOWN functions like memcpy
                failed = fail_ref.get(FAILED)
                if failed:
                    # When does this case happen?
                    return inst, failed
                else:
                    sat = _check_if_known_func_condition_is_met(inst, info)
                    return inst, not sat
            fail_ref.set(FAILED, YES)
            return inst, YES

        if not func.may_succeed:
            # debug(func.name, 'function may not succeed')
            return inst, YES

        # Do not process body of a function multiple times
        if func.name not in _have_processed:
            # Go into the functions and mark boundary
            with remember_func(func):
                with info.sym_tbl.with_func_scope(inst.name):
                    body = _do_pass(func.body, info, PassObject())
            assert body is not None, 'this pass should not remove anything'
            func.body = body
            _have_processed.add(func.name)

        if current_function:
            # Update the current function with the failure paths
            current_function.path_ids.extend(func.path_ids)
    elif inst.kind == ANNOTATION_INST and inst.ann_kind == Annotation.ANN_SKIP:
        fail_ref.set(FAILED, YES)
        return inst, YES

    failed = fail_ref.get(FAILED)
    return inst, failed


def _to_userspace(i, info, body):
    global failure_path_id
    to_user_inst = ToUserspace.from_func_obj(current_function)
    to_user_inst.path_id = failure_path_id
    failure_path_id += 1
    body.append(to_user_inst)
    # debug(MODULE_TAG, 'new failure path:', to_user_inst.path_id)

    if current_function:
        current_function.path_ids.append(to_user_inst.path_id)


def _process_child(child, inst, info, more):
    lvl, tag, parent_list = more.unpack()
    new_child = None
    if isinstance(child, list):
        new_child = []
        obj = more.repack(lvl + 1, tag, new_child)
        for i in child:
            new_inst = _process_child(i, inst, info, obj)
            if new_inst is None:
                if inst.kind == BLOCK_OF_CODE and inst.tag == BODY:
                    # It is a block of code, we do not want to remove the whole
                    # block just stop here.
                    break
                else:
                    # The argument, condition or ... of this instruction was
                    # not possible. Also remove the whole instruction.
                    return None
            new_child.append(new_inst)
    else:
        obj = more.repack(lvl + 1, tag, parent_list)
        new_child = _do_pass(child, info, obj)

    return new_child


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
    new_children = []
    failed = fail_ref.get(FAILED)

    if failed or inst.bpf_ignore:
        return clone_pass(inst, info, PassObject())

    with cb_ref.new_ref(ctx, parent_list):
        inst, failed = _process_current_inst(inst, info, more)
        assert inst is not None, 'This pass should not remove any instruction'
        if failed == YES:
            blk = cb_ref.get(BODY)
            _to_userspace(inst, info, blk)
            text, _ = gen_code([inst], info)
            current_func_name = current_function.name if current_function is not None else 'NOT SET'
            # debug(MODULE_TAG, 'Go to userspace at instruction:', text, f'@{current_func_name}')
            failed = MARKED
            fail_ref.set(FAILED, failed)
            return clone_pass(inst, info, PassObject())
        elif failed == MARKED:
            # We might not see any split point in this function, but functions
            # called from this function have split points
            return clone_pass(inst, info, PassObject())
        else:
            # Continue deeper
            for child, tag in inst.get_children_context_marked():
                with fail_ref.new_ref(FAILED, failed):
                    obj = PassObject.pack(lvl + 1, tag, parent_list)
                    with cb_ref.new_ref(PARENT_INST, inst):
                        new_child = _process_child(child, inst, info, obj)
                        assert new_child is not None, 'This pass should not remove any instruction'
                    failed = fail_ref.get(FAILED)

                # TODO: when should I propagate the failure to the upper level context?
                parent = cb_ref.get(PARENT_INST)
                if parent is None or parent.kind not in (clang.CursorKind.IF_STMT, clang.CursorKind.CASE_STMT):
                    fail_ref.set(FAILED, failed)
                    # debug(MODULE_TAG, 'propagate failure: ', inst.kind, inst)

                new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def mark_user_boundary_pass(inst, info, more):
    """
    Assumption: The information about function failures is needed 
    Find and mark the User/BPF boundaries. Mark with ToUserspace instruction.
    """
    global current_function
    global cb_ref
    global fail_ref
    global _have_processed
    current_function = more.get('func')
    cb_ref = CodeBlockRef()
    fail_ref = CodeBlockRef()
    _have_processed = set()

    with cb_ref.new_ref(PARENT_INST, None):
        with fail_ref.new_ref(FAILED, NO):
            return _do_pass(inst, info, more)
