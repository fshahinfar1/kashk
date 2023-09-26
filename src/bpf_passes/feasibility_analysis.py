from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from prune import READ_PACKET, WRITE_PACKET
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from passes.clone import clone_pass


MODULE_TAG = '[Feasibility Pass]'
FAILED = 999
PARENT_INST = 1000

current_function = None
cb_ref = CodeBlockRef()
fail_ref = CodeBlockRef()


@contextmanager
def remember_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield None
    finally:
        current_function = tmp


def is_function_call_feasible(inst, info):
    func = inst.get_function_def()
    if not func:
        if inst.name in ('memcpy', *READ_PACKET, *WRITE_PACKET):
            # It is fine
            return True
        return False
    if func.is_empty():
        if inst.name in ('memcpy', *READ_PACKET, *WRITE_PACKET):
            # It is fine
            return True

        func.may_fail = True
        return False

    with remember_func(func):
        with info.sym_tbl.with_func_scope(inst.name):
            modified = _do_pass(func.body, info, PassObject())

    func.body = modified
    if modified is None:
        return False
    return True


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        res = is_function_call_feasible(inst, info)
        if not res:
            return inst, True

        # Check if the function may fail
        func = inst.get_function_def()
        if func and current_function and func.may_fail:
            # The called function may fail
            current_function.may_fail = True
            # We might not see any split point in this function, but functions
            # called from this function have split points
            current_function.path_ids.extend(func.path_ids)
    return inst, False


failure_path_id = 1
def _failed_to_generate_inst(i, info, body):
    global failure_path_id
    to_user_inst = ToUserspace.from_func_obj(current_function)
    to_user_inst.path_id = failure_path_id
    failure_path_id += 1
    body.append(to_user_inst)
    debug(MODULE_TAG, 'new failure path:', to_user_inst.path_id)

    if current_function:
        current_function.may_fail = True
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

    if inst.bpf_ignore is True:
        new_inst = clone_pass(inst, info, PassObject())
        return new_inst

    with cb_ref.new_ref(ctx, parent_list):
        if failed:
            inst, failed = inst, failed
        else:
            inst, failed = _process_current_inst(inst, info, more)
            if failed:
                blk = cb_ref.get(BODY)
                _failed_to_generate_inst(inst, info, blk)
                text, _ = gen_code([inst], info)
                debug(MODULE_TAG, 'Go to userspace at instruction:', text)
                # Not a stack
                fail_ref.set(FAILED, True)
            elif inst.kind == clang.CursorKind.CALL_EXPR:
                tmp_func = inst.get_function_def()
                assert tmp_func is not None
                if tmp_func.may_fail and not tmp_func.may_succeed:
                    # This function is definitely failing
                    failed = True
                    # TODO: maybe generate the fallback here instead of in another pass

        if inst is None:
            # This instruction should be removed
            return None

        # Continue deeper
        for child, tag in inst.get_children_context_marked():
            with fail_ref.new_ref(FAILED, failed):
                obj = PassObject.pack(lvl + 1, tag, parent_list)
                with cb_ref.new_ref(PARENT_INST, inst):
                    new_child = _process_child(child, inst, info, obj)
                if new_child is None:
                    return None
                failed = fail_ref.get(FAILED)

            # TODO: when should I propagate the failure to the upper level
            # context?
            parent = cb_ref.get(PARENT_INST)
            if parent is None or parent.kind != clang.CursorKind.IF_STMT:
                fail_ref.set(FAILED, failed)
                # debug(MODULE_TAG, 'propagate failure: ', inst.kind, inst)

            new_children.append(new_child)

            if current_function and not failed and inst.kind == clang.CursorKind.RETURN_STMT:
                current_function.may_succeed = True

    new_inst = inst.clone(new_children)
    return new_inst


def feasibilty_analysis_pass(inst, info, more):
    with cb_ref.new_ref(PARENT_INST, None):
        with fail_ref.new_ref(FAILED, False):
            return _do_pass(inst, info, more)
