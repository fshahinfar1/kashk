import itertools
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code


MODULE_TAG = '[Possible Path Pass]'


def is_function_call_possible(inst, info):
    func = inst.get_function_def()
    if not func:
        return False

    with info.sym_tbl.with_func_scope(inst.name):
        modified = _do_pass(func.body, info, (0, BODY, None))
    func.body = modified
    if modified is None:
        return False
    return True


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        res = is_function_call_possible(inst, info)
        debug(inst.name, 'is possible:', res)
        if not res:
            return None
    return inst


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more
    new_children = []

    # Process current instruction
    inst = _process_current_inst(inst, info, more)

    if inst is None:
        # This instruction should be removed
        return None

    # Continue deeper
    for child, tag in inst.get_children_context_marked():
        if isinstance(child, list):
            new_child = []
            for i in child:
                new_inst = _do_pass(i, info, (lvl+1, tag, new_child))
                if new_inst is None:
                    assert inst.kind == BLOCK_OF_CODE
                    if inst.tag == BODY:
                        # TODO: stop proceeding in this path and go to the userspace
                        tmp, _ = gen_code([i], info)
                        comment = f'/* can not use "{tmp}". Continue in userspace!*/'
                        tmp_inst = Literal(comment, CODE_LITERAL)
                        new_child.append(tmp_inst)
                        break
                    else:
                        # The argument of something similar is removed
                        return None
                new_child.append(new_inst)
        else:
            new_child = _do_pass(child, info, (lvl+1, tag, parent_list))
            if new_child is None:
                # The child of this instruction was removed
                # Probably this instruction should also be removed
                return None

        new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def possible_path_analysis_pass(inst, info, more):
    return _do_pass(inst, info,more)
