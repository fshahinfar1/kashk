from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from utility import implies
from data_structure import *
from instruction import *

from passes.pass_obj import PassObject


MODULE_TAG = '[Select Userspace Pass]'


NODE = 128
STATE = 234
cb_ref = None
node_ref = None
to_user_ref = None
state_ref = None


def _process_call_inst(inst, info, more):
    func = inst.get_function_def()
    if not func or func.is_empty() or not func.may_fail:
        return

    parent_node = node_ref.get(NODE)
    node = parent_node.new_child()
    # Step inside the function
    # debug('Investigate:', inst.name)
    with node_ref.new_ref(NODE, node):
        with info.sym_tbl.with_func_scope(func.name):
            with state_ref.new_ref(STATE, (False, None)):
                ret = _do_pass(func.body, info, PassObject())
        # It is important that the code which check the user_graph_node
        # be in the context of "graph_node(node)"
        tmp_node = node_ref.get(NODE)
        if tmp_node.is_empty():
            tmp_node.remove()


def _do_pass(inst, info, more):
    lvl = more.lvl
    ctx = more.ctx

    in_user_land, remember = state_ref.get(STATE)
    if in_user_land:
        remember.append(inst)
        return

    if inst.kind == TO_USERSPACE_INST:
        # debug('reach "to user space inst"')
        state_ref.set(STATE, (True, []))
        to_user_ref.push(TO_USERSPACE_INST, inst)
        return
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        _process_call_inst(inst, info, more)

    with cb_ref.new_ref(inst.kind, inst):
        for child, tag in inst.get_children_context_marked():
            if not isinstance(child, list):
                child = [child]

            boundary_begin_flag = False
            boundary_end_flag = False
            for i in child:
                in_user_land, remember = state_ref.get(STATE)
                if in_user_land:
                    remember.append(i)
                    continue

                # Look deeper
                obj = more.repack(lvl+1, tag, None)
                with state_ref.new_ref(STATE, (in_user_land, remember)):
                    ret = _do_pass(i, info, obj)
                    prev_signal = in_user_land
                    cur_signal, new_remember = state_ref.get(STATE)

                # TODO: the propagation might be to the parent of parent not the immidiate parent
                # Propagate signal
                state_ref.set(STATE, (cur_signal, new_remember))
                in_user_land, remember = state_ref.get(STATE)
                assert remember == new_remember and (implies(cur_signal, new_remember is not None))

                boundary_begin_flag = cur_signal and not prev_signal
                boundary_end_flag = not cur_signal and prev_signal

                if boundary_begin_flag:
                    # TODO: Do I expect each node to start with ToUserspace instructions?
                    remember.append(i)
                elif boundary_end_flag:
                    user_inst = Block(BODY)
                    user_inst.extend_inst(remember)
                    node = node_ref.get(NODE)
                    path = node.append(user_inst)
                    path.original_scope = info.sym_tbl.current_scope

                    to_user_inst_ref = to_user_ref.get(TO_USERSPACE_INST)
                    to_user = remember[0]
                    assert to_user == to_user_inst_ref, 'Each user space code block should be started with a ToUserspace instruction!'

                    path.to_user_inst = to_user_inst_ref
                    node.set_id(to_user_inst_ref.path_id)
                    # TODO: this type of managing the state is very tricky. what the hell!
                    to_user_ref.pop() # the TO_USERSPACE_INST was consumed!
                    # debug(MODULE_TAG, 'TO USERSPACE dead', to_user_inst_ref.path_id)

                    # Create a new node
                    new_node = node.parent.new_child()
                    node_ref.set(NODE, new_node)


def select_user_pass(inst, info, more):
    """
    Description:
    Creates the graph describing how different failure paths should be handled
    in userspace program.

    Assumption:
    The functions that may fail have been marked in previous passes.

    How It Works:

    1. Create the first node of the graph (root)
    2. Walk the instructions in DFS order
    3. If encounter a ToUserspace instruction, it is begining of a failure path.  
    4. Add all instructions that are executed after this ToUserspace until end of CFG.
    5. Continue the DFS search
    """
    global cb_ref
    global node_ref
    global to_user_ref
    global state_ref

    raise Exception('This modules is very buggy and I am trying to replace/discontinue it!')

    cb_ref = CodeBlockRef()
    node_ref = CodeBlockRef()
    to_user_ref = CodeBlockRef()
    state_ref = CodeBlockRef()

    # Initialize the pass
    node = info.user_prog.graph.new_child()
    with node_ref.new_ref(NODE, node):
        with state_ref.new_ref(STATE, (False, None)):
            # Performe the pass
            _do_pass(inst, info, more)
            # Clean up
            node = node_ref.get(NODE)
            if node.is_empty():
                node.remove()
