from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from prune import READ_PACKET, WRITE_PACKET
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from passes.clone import clone_pass

from bpf_passes.mark_user_boundary import mark_user_boundary_pass


MODULE_TAG = '[Feasibility Pass]'
FAILED = 999
PARENT_INST = 1000

current_function = None
cb_ref = None
fail_ref = None


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
    if not func or func.is_empty():
        if inst.name in ('memcpy', *READ_PACKET, *WRITE_PACKET):
            # It is fine
            return True
        func.may_fail = True
        return False

    with remember_func(func):
        with info.sym_tbl.with_func_scope(inst.name):
            body = _do_pass(func.body, info, PassObject())

    assert body is not None, 'this pass should not remove anything'
    func.body = body
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
    return inst, False


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

    if failed or inst.bpf_ignore is True:
        return clone_pass(inst, info, PassObject())

    with cb_ref.new_ref(ctx, parent_list):
        inst, failed = _process_current_inst(inst, info, more)
        assert inst is not None
        if failed:
            if current_function:
                current_function.may_fail = True
            # Not a stack
            fail_ref.set(FAILED, True)

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

        # NOTE: make sure this if is out of the for block (You have messed up once) :)
        if current_function and not failed and inst.kind == clang.CursorKind.RETURN_STMT:
            current_function.may_succeed = True

    new_inst = inst.clone(new_children)
    return new_inst


def _do_feasibility_analisys(inst, info, more):
    global current_function
    global cb_ref
    global fail_ref
    current_function = more.get('func')
    cb_ref = CodeBlockRef()
    fail_ref = CodeBlockRef()

    with cb_ref.new_ref(PARENT_INST, None):
        with fail_ref.new_ref(FAILED, False):
            return _do_pass(inst, info, more)


def feasibilty_analysis_pass(inst, info, more):
    # Start the analysis from the given function and perform it on the all know
    # functions.
    res = _do_feasibility_analisys(inst, info, more)
    for func in Function.directory.values():
        if func.may_succeed or func.may_fail:
            continue
        if func.is_empty():
            func.may_fail = True
            func.may_succeed = False
            continue
        obj = PassObject()
        obj.func = func
        _do_feasibility_analisys(func.body, info, obj)
        # debug(func.return_type, func.name, func.may_fail, func.may_succeed, func.body.children)
        assert func.may_fail or func.may_succeed, 'After this processing we should have decide if function can fail or not'

    res = mark_user_boundary_pass(res, info, PassObject())
    return res
