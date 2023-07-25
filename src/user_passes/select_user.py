from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject


MODULE_TAG = '[Select Userspace Pass]'


NODE = 128
cb_ref = CodeBlockRef()


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

    assert more.in_user_land is False

    # if inst.kind != BLOCK_OF_CODE:
    #     debug(f'{lvl:3d}', ("|" * lvl) + '+->', inst, f'(signal:{more.in_user_land})')

    if inst.kind == TO_USERSPACE_INST:
        # debug('reach "to user space inst"')
        _set_in_userland(more)
        # TODO: what am I doing
        print('TO USERSPACE found')
        cb_ref.push(TO_USERSPACE_INST, inst)
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        func = inst.get_function_def()
        if func and func.body.has_children():
            parent_node = cb_ref.get(NODE)
            node = parent_node.new_child()
            # Step inside the function
            # debug('Investigate:', inst.name)
            obj = more.repack(0, None, None)
            with cb_ref.new_ref(NODE, node):
                with info.sym_tbl.with_func_scope(func.name):
                    ret = _do_pass(func.body, info, obj)
                # It is important that the code which check the user_graph_node
                # be in the context of "graph_node(node)"
                node = cb_ref.get(NODE)
                if node.is_empty():
                    node.remove()
            # debug (f'step out of function: {inst.name} and userland state in function is: {obj.in_user_land}')

            # Propagate the signal to caller context
            if func.may_fail:
                # If we have already failed, then why are we considering this paths?
                assert more.in_user_land is False
                _set_in_userland(more)
                print('The function may fail!')

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
                    print('new boundry era')

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
            node = cb_ref.get(NODE)
            path = node.append(user_inst)
            path.original_scope = info.sym_tbl.current_scope

            to_user_inst_ref = cb_ref.get(TO_USERSPACE_INST)
            if to_user_inst_ref is not None:
                assert to_user_inst_ref is not None
                path.to_user_inst = to_user_inst_ref
                # TODO: this type of managing the state is very tricky. what the hell!
                cb_ref.pop() # the TO_USERSPACE_INST was consumed! 
                print('TO USERSPACE dead')

            # Set the signal off! do not propagate.
            _init_userland_signal(more)
            # Create a new node
            new_node = node.parent.new_child()
            cb_ref.set(NODE, new_node)


def select_user_pass(inst, info, more):
    # Initialize the pass
    _init_userland_signal(more)
    node = info.user_prog.graph.new_child()
    with cb_ref.new_ref(NODE, node):
        # Performe the pass
        _do_pass(inst, info, more)
        # Clean up
        node = cb_ref.get(NODE)
        if node.is_empty():
            node.remove()
