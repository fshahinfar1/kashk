from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code


MODULE_TAG = '[Possible Path Pass]'

current_function = None
has_failed = False
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


@contextmanager
def remember_boundry(ctx, value):
    global has_failed
    if ctx == BODY:
        tmp = has_failed
        has_failed = value
        try:
            yield None
        finally:
            name = 'empty'
            if current_function:
                name = current_function.name
            # debug('put it back', has_failed, tmp, 'at', name)
            has_failed = tmp
    else:
        # Do nothing
        try:
            yield None
        finally:
            # debug('do nothing', has_failed)
            pass


def is_function_call_possible(inst, info):
    func = inst.get_function_def()
    if not func:
        if inst.name in ('memcpy', ):
            # It is fine
            return True
        # debug('function is not possible (no def):', inst.name)
        return False

    with remember_func(func):
        with info.sym_tbl.with_func_scope(inst.name):
            modified = _do_pass(func.body, info, (0, BODY, None))

    func.body = modified
    if modified is None:
        # debug('function is not possible (no body):', inst.name)
        return False
    return True


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        res = is_function_call_possible(inst, info)
        # debug(inst.name, 'is possible:', res)
        if not res:
            return inst, True

        # Check if the function may fail
        func = inst.get_function_def()
        if func and current_function and func.may_fail:
            current_function.may_fail = True
    return inst, False


def _failed_to_generate_inst(i, info, body):
    # TODO: this function is probably is not needed anymore
    tmp, _ = gen_code([i], info)
    comment = f'/* can not use "{tmp}". Removing it!*/'
    tmp_inst = Literal(comment, CODE_LITERAL)
    body.append(tmp_inst)

    if current_function:
        current_function.may_fail = True

def _process_child(child, inst, info, lvl, tag, parent_list):
    new_child = None
    if isinstance(child, list):
        new_child = []
        for i in child:
            new_inst = _process_child(i, inst, info, lvl, tag, new_child)
            if new_child is None:
                if inst.kind == BLOCK_OF_CODE and inst.tag == BODY:
                    # It is a block of code, we do not want to remove the whole
                    # block just stop here.
                    _failed_to_generate_inst(child, info, parent_list)
                    break
                else:
                    # The argument, condition or ... of this instruction was
                    # not possible. Also remove the whole instruction.
                    return None
            new_child.append(new_inst)
    else:
        new_child = _do_pass(child, info, (lvl+1, tag, parent_list))
    return new_child


def _do_pass(inst, info, more):
    global has_failed
    lvl, ctx, parent_list = more
    new_children = []

    # debug('T' if has_failed else 'F', '|' * lvl, '\'-->' , inst, '  context:', ctx)

    with cb_ref.new_ref(ctx, parent_list):
        if not has_failed:
            # Process current instruction
            inst, fails = _process_current_inst(inst, info, more)
        else:
            inst, fails = inst, False

        if inst is None:
            # This instruction should be removed
            return None

        if fails and not has_failed:
            # debug('>>>> It fails here <<<<')
            has_failed = True
            to_user_inst = ToUserspace.from_func_obj(current_function)
            blk = cb_ref.get(BODY)
            blk.append(to_user_inst)

        # Continue deeper
        for child, tag in inst.get_children_context_marked():
            with remember_boundry(tag, has_failed):
                new_child = _process_child(child, inst, info, lvl, tag, parent_list)
            if new_child is None:
                return None
            new_children.append(new_child)

            if inst.kind == clang.CursorKind.RETURN_STMT:
                current_function.may_succeed = True

    new_inst = inst.clone(new_children)
    return new_inst


def possible_path_analysis_pass(inst, info, more):
    return _do_pass(inst, info,more)
