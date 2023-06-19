from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject


MODULE_TAG = '[Select Userspace Pass]'
user_graph_node = None

@contextmanager
def graph_node(node):
    global user_graph_node
    tmp = user_graph_node
    user_graph_node = node
    try:
        yield None
    finally:
        user_graph_node = tmp


def _propagate_userland_signal(old, new):
    old.in_user_land = new.in_user_land
    old.remember = new.remember


def _set_in_userland(obj):
    obj.in_user_land = True
    obj.remember = []


def _init_userland_signal(obj):
    obj.in_user_land = False
    obj.remember = None


def _do_pass(inst, info, more):
    lvl = more.lvl
    ctx = more.ctx
    if not hasattr(more, 'in_user_land'):
        _init_userland_signal(more)

    assert more.in_user_land is False

    # if inst.kind != BLOCK_OF_CODE:
    #     debug(f'{lvl:3d}', ("|" * lvl) + '+->', inst, f'(signal:{more.in_user_land})')

    if inst.kind == TO_USERSPACE_INST:
        # debug('reach "to user space inst"')
        _set_in_userland(more)
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        func = inst.get_function_def()
        if func:
            node = user_graph_node.new_child()
            # Step inside the function
            # debug('Investigate:', inst.name)
            obj = PassObject()
            with graph_node(node):
                with info.sym_tbl.with_func_scope(inst.name):
                    ret = _do_pass(func.body, info, obj)
                if node.is_empty():
                    node.remove()
            # debug (f'step out of function: {inst.name} and userland state in function is: {obj.in_user_land}')

            # Propagate the signal to caller context
            if func.may_fail:
                _set_in_userland(more)

    for child, tag in inst.get_children_context_marked():
        if not isinstance(child, list):
            child = [child]

        boundy_begin_flag = False
        for i in child:
            if not more.in_user_land:
                # Look deeper
                obj = more.repack(lvl+1, tag, None)
                ret = _do_pass(i, info, obj)

                prev_signal = more.in_user_land
                cur_signal =  obj.in_user_land

                _propagate_userland_signal(more, obj)

                # The nearest BLOCK which contains the failure
                if tag == BODY and cur_signal and not prev_signal:
                    boundy_begin_flag = True

            if more.in_user_land and boundy_begin_flag:
                # debug(f'{lvl:3d}', ("|" * lvl * 1) + '+->', '(selected)', inst)
                if i.kind == TO_USERSPACE_INST:
                    # do not add this instruction to the list
                    continue
                more.remember.append(i)

        if boundy_begin_flag:
            # The userland boundy was found in this block. And this block
            # has ended.

            # debug('---------------------------------')
            # debug('## number of user inst:', len(more.remember))
            # debug(more.remember)
            # debug('---------------------------------')

            # TODO: I might want to postpone this to the upper block

            user_inst = Block(BODY)
            user_inst.extend_inst(more.remember)
            user_graph_node.append(user_inst)

            # Set the signal off! do not propagate.
            _init_userland_signal(more)


def select_user_pass(inst, info, more):
    # Initialize the pass
    with graph_node(info.user_prog.graph):
        return _do_pass(inst, info, more)
