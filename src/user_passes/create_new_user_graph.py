from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from data_structure import CodeBlockRef
from instruction import *

from cfg import CFGBaseNode


NODE = 128
STATE = 234
MODULE_TAG = '[CREATE NEW USER GRAPH]'
node_ref = None
state_ref = None

def _fill_the_user_graph_node(insts, node, info):
    blk = Block(BODY)
    to_user_inst = insts[0]
    blk.extend_inst(insts[1:])
    path = node.append(blk)
    path.original_scope = info.sym_tbl.current_scope
    assert to_user_inst.kind == TO_USERSPACE_INST, 'Each user space code block should be started with a ToUserspace instruction!'
    path.to_user_inst = to_user_inst
    node.set_id(to_user_inst.path_id)

def _go_through_insts(node, info):
    user_land, insts = state_ref.get(STATE)
    for inst in node.insts:
        if inst.kind == TO_USERSPACE_INST:
            # Entering fallback region (User land)
            user_land = True
            insts = []
            state_ref.set(STATE, (user_land, insts))

        if user_land:
            insts.append(inst)
    _do_pass(node.next, info)

def _process_jmps(jmps, info):
    user_land, insts = state_ref.get(STATE)
    parent_node = node_ref.get(NODE)
    for _, j in jmps:
        if not j:
            continue
        # NOTE: We want to go back to the previous user_land and insts when finish
        # observing a path. That is why a stack is used here.
        with state_ref.new_ref(STATE, (user_land, insts)):
            node = parent_node.new_child()
            with node_ref.new_ref(NODE, node):
                _do_pass(j, info)

                node = node_ref.get(NODE) # NOTE: Not necessary the same node as defined before the context
                new_flag, new_insts = state_ref.get(STATE)
                boundary_end_flag = new_flag and not user_land
                if boundary_end_flag:
                    _fill_the_user_graph_node(new_insts, node, info)
                if node.is_empty():
                    node.remove()

            
def _do_pass(cfg, info):
    if cfg is None:
        return
    root = cur = cfg
    if cur.kind == CFGBaseNode.Simple:
        _go_through_insts(cur, info)
        cur = cur.next
    elif cur.kind == CFGBaseNode.Branch:
        # NOTE: assuming the condition instruction does not fail. It is
        # valid because the linear pass should have ran before this.
        jmps = [(None, cur.if_true), (None, cur.if_false)]
        _process_jmps(jmps, info)
    elif cur.kind == CFGBaseNode.Switch:
        _process_jmps(cur.jmps, info)
    else:
        raise Exception('Unexpected')


def create_new_user_graph(cfg, info, more):
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

    global node_ref
    global state_ref
    node_ref = CodeBlockRef()
    state_ref = CodeBlockRef()
    node = info.user_prog.graph.new_child()
    with node_ref.new_ref(NODE, node):
        with state_ref.new_ref(STATE, (False, None)):
            _do_pass(cfg, info)
            new_flag, new_insts = state_ref.get(STATE)
            node = node_ref.get(NODE) # NOTE: Not necessary the same node as defined before the context
            if new_flag:
                # There is a failure
                _fill_the_user_graph_node(new_insts, node, info)
            if node.is_empty():
                node.remove()
