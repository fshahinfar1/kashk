from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from prune import READ_PACKET, WRITE_PACKET
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from passes.clone import clone_pass


MODULE_TAG = '[Possible Path Pass]'

current_function = None
cb_ref = CodeBlockRef()


@contextmanager
def remember_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield None
    finally:
        current_function = tmp


def is_function_call_possible(inst, info):
    func = inst.get_function_def()
    if not func:
        if inst.name in ('memcpy', READ_PACKET, WRITE_PACKET):
            # It is fine
            return True
        # debug('function is not possible (no def):', inst.name)
        return False

    with remember_func(func):
        with info.sym_tbl.with_func_scope(inst.name):
            modified = _do_pass(func.body, info, PassObject())

    func.body = modified
    if modified is None:
        # debug('function is not possible (no body):', inst.name)
        return False
    return True


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        res = is_function_call_possible(inst, info)
        if not res:
            return inst, True

        # Check if the function may fail
        func = inst.get_function_def()
        if func and current_function and func.may_fail:
            # The called function may fail
            current_function.may_fail = True
    return inst, False


def _failed_to_generate_inst(i, info, body):
    to_user_inst = ToUserspace.from_func_obj(current_function)
    body.append(to_user_inst)

    if current_function:
        current_function.may_fail = True


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

    more.failed = obj.failed

    return new_child


def _do_pass(inst, info, more):
    # TODO: fix this ugly if-else
    lvl, ctx, parent_list = more.unpack()
    new_children = []
    failed = more.get('failed', False)

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
                # debug(MODULE_TAG, 'Go to userspace at instruction:', text)
                more.failed = failed

        if inst is None:
            # This instruction should be removed
            return None

        # Continue deeper
        for child, tag in inst.get_children_context_marked():
            obj = PassObject.pack(lvl, tag, parent_list)
            obj.failed = failed
            new_child = _process_child(child, inst, info, obj)
            if new_child is None:
                return None

            failed = obj.failed
            # TODO: when should I propagate the failure to the upper level
            # context?
            if inst.kind != clang.CursorKind.IF_STMT:
                more.failed = failed

            new_children.append(new_child)

            if not failed and inst.kind == clang.CursorKind.RETURN_STMT:
                current_function.may_succeed = True

    new_inst = inst.clone(new_children)
    return new_inst


def possible_path_analysis_pass(inst, info, more):
    return _do_pass(inst, info, more)
