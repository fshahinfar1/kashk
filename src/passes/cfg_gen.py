from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *
from cfg import *

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject


MODULE_TAG = '[CFG Gen Pass]'


def is_branching(inst):
    return inst.kind in (clang.CursorKind.IF_STMT, clang.CursorKind.SWITCH_STMT,
            clang.CursorKind.CALL_EXPR)


def _do_pass(inst, info, more):
    lvl = more.lvl
    ctx = more.ctx
    new_children = []

    # TODO: do something
    if is_branching(inst):
        pass

    for child, tag in inst.get_children_context_marked():
        flag_is_list = isinstance(child, list)
        if not flag_is_list:
            child = [child]

        new_child = []

        for i in child:
            # Look deeper
            obj = more.repack(lvl+1, tag, None)
            clone = _do_pass(i, info, obj)
            new_child.append(clone)

        if not flag_is_list:
            new_child = new_child.pop()
        new_children.append(new_child)

    

    new_inst = inst.clone(new_children)
    return new_inst


def select_user_pass(inst, info, more):
    return _do_pass(inst, info, more)
