"""
Calculate the cost of basic-blocks. It is used in determining the
"""
from log import debug
from instruction import InstructionColor
from passes.code_pass import Pass
from data_structure import Function
from cfg import CFGJump, CFGNode, Jump
from brain.basic_block import BasicBlock, inst_is_func_call
from brain.exec_path import ExecutionBlock

MODULE_TAG = '[Cost Func]'


context_switch = 10750
def set_context_switch_cost(val):
    global context_switch
    context_switch = val


def consult_inst_cost_table(inst):
    table = {
            InstructionColor.ORIGINAL: 0,
            InstructionColor.RED: 0,
            InstructionColor.CHECK: 0.5,
            InstructionColor.MAP_LOOKUP: 2,
            InstructionColor.KNOWN_FUNC_IMPL: 0,
            InstructionColor.EXTRA_STACK_ALOC: 0,
            InstructionColor.EXTRA_MEM_ACCESS: 1,
            InstructionColor.REMOVE_READ: -context_switch,
            InstructionColor.REMOVE_WRITE: -context_switch,
            InstructionColor.ADD_ARGUMENT: 0,
            InstructionColor.EXTRA_ALU_OP: 0,
            InstructionColor.MEM_COPY: 0,
            InstructionColor.TO_USER: context_switch,
        }
    # debug(inst.color, tag=MODULE_TAG)
    if inst.color == InstructionColor.KNOWN_FUNC_IMPL:
        know_func_table = {
                'bpf_map_lookup_elem': table[InstructionColor.MAP_LOOKUP],
                'bpf_xdp_adjust_tail': 5,
                '__prepare_headers_before_send': 20,
                '__prepare_headers_before_pass': 20,
                '__adjust_skb_size': 10,
                }
        return know_func_table[inst.name]
    return table[inst.color]


def basic_block_cost_func(block, cost_table):
    """
    Determine the cost of given basic-block
    @param block, a basic block
    @param cost_table, a table which holds the cost calculated for the
    functions
    """
    assert isinstance(block, BasicBlock)
    if len(block.insts) == 0:
        # Special case in which the block is empty
        return 0
    elif block.is_func_call():
        first_inst = block.insts[0]
        call_inst = inst_is_func_call(first_inst)
        func = Function.directory.get(call_inst.name)
        if func is None or func.is_empty() or not func.is_used_in_bpf_code:
            if call_inst.is_modified():
                return consult_inst_cost_table(call_inst)
            return 0
        cost = cost_table[call_inst.name]
        return cost
    elif block.is_red():
        cost = 0
        for inst in block.insts:
            tmp = consult_inst_cost_table(inst)
            cost += tmp
        return cost
    else:
        # Just original instructions
        return 0


def _execution_block_exp_cost(exec_block, cost_table):
    exp_cost = 0
    count = 0
    for path in exec_block.paths:
        tmp = calculate_cost_along_path(path, cost_table)
        if path.unlikely:
            continue
        exp_cost += tmp
        count += 1
    exp_cost = round(exp_cost / count, 3)
    return exp_cost


def calculate_cost_along_path(path, cost_table):
    """
    @param cost_table: a table defining the cost of calling a function
    """
    acc = 0
    for block in path.blocks:
        if isinstance(block, ExecutionBlock):
            debug('an execution block: How many times does it repeat?', tag=MODULE_TAG)
            N = 1
            if block.exp_cost is None:
                cost = _execution_block_exp_cost(block, cost_table)
                block.exp_cost = cost
            else:
                cost = block.exp_cost
            acc += N * cost
            continue
        cost = basic_block_cost_func(block, cost_table)
        acc += cost
        block.cost_book[path.id] = acc
    return acc


class CalcExpectedCost(Pass):
    """
    Pass over the nodes of CFG and update expected cost of each block
    """
    def process_current_inst(self, node, more):
        if node.node_id in self._visited_ids:
            # We have processed this node. We have either processed its
            # children or we are in middle of processing them.
            self.skip_children()
            return node
        if isinstance(node, CFGJump):
            return node
        if not isinstance(node, BasicBlock):
            raise Exception('Unexpected')
        count_paths = len(node.cost_book.keys())
        if count_paths == 0:
            exp = 0
        else:
            exp = round(sum(node.cost_book.values()) / count_paths, 3)
        node.expected_cost = exp
        return node
