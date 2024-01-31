"""
Calculate the cost of basic-blocks. It is used in determining the
"""
from log import debug
from code_pass import Pass
from data_structure import Function
from cfg import CFGJump, CFGNode
from brain.basic_block import BasicBlock
from brain.basic_block import inst_is_func_call

MODULE_TAG = '[Cost Func]'


def consult_inst_cost_table(inst):
    return 0


def basic_block_cost_func(block, cost_table):
    """
    Determine the cost of given basic-block
    @param block, a basic block
    @param cost_table, a table which holds the cost calculated for the
    functions
    """
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


def calculate_cost_along_path(path, cost_table):
    """
    @param cost_table: a table defining the cost of calling a function
    """
    acc = 0
    for block in path.blocks:
        cost = basic_block_cost_func(block, cost_table)
        acc += cost
        block.cost_book[path.id] = acc


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
        count_paths = len(block.cost_book.keys())
        exp = round(sum(block.cost_book.values()) / count_paths, 3)
        block.expected_cost = exp
        return node
