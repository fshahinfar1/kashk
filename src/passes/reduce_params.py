import clang.cindex as clang
from log import error, debug
from data_structure import *
from instruction import *


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more
    new_children = []

    # Continue deeper
    for child, tag in inst.get_children_context_marked():
        if isinstance(child, list):
            new_child = []
            for i in child:
                new_inst = _do_pass(i, info, (lvl+1, tag, new_child))
                if new_inst is None:
                    continue
                new_child.append(new_inst)
        else:
            new_child = _do_pass(child, info, (lvl+1, tag, None))
            assert new_child is not None
        new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def reduce_params_pass(inst, info, more):
    return _do_pass(inst, info, more)
