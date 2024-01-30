"""
Decide what part of the user program to offload
"""
from math import inf
from cfg import CFGJump, CFGNode
from code_pass import Pass

from log import debug
from brain.basic_block import create_basic_block_cfg, _inst_is_func_call
from brain.exec_path import extract_exec_paths
from helpers.cfg_graphviz import CFGGraphviz


MODULE_TAG = '[Analyze Program]'


# NOTE: The evaluation function is path independent, use memoizing, otherwise
# there will be too many traverses.

class SelectBoundaries(Pass):
    def __init__(self, info):
        super().__init__(info)
        self.cur_min = inf
        self.cur_sel = None
        self.selected_blocks = []
        self.entry_node = None

    def process_current_inst(self, node, more):
        if node.node_id in self._visited_ids:
            self.skip_children()
            return node
        # TODO: this is not very good way to find the first node we are
        # processing in this pass.
        if self.entry_node is None:
            self.entry_node = node
        if isinstance(node, CFGJump):
            for branch in node.jmps:
                tmp = SelectBoundaries.do(branch.target, self.info)
                blocks_for_this_branch = tmp.selected_blocks
                # TODO: there may be conflicts along the paths. I think not
                # handling conflicts would be fine for now.
                self.selected_blocks.extend(blocks_for_this_branch)
            self.skip_children()
            return node
            # END
        elif isinstance(node, CFGNode):
            for block in node.insts:
                if block.expected_cost < self.cur_min:
                    self.cur_sel = block
                    self.cur_min = block.expected_cost
        return node

    def end_current_inst(self, node, more):
        if node == self.entry_node:
            # we are exiting the evaluation of the root
            # What was the choice?
            tmp = (self.cur_sel, self.cur_min)
            self.selected_blocks.append(tmp)
            # END


class CalcExpectedCost(Pass):
    def process_current_inst(self, node, more):
        if node.node_id in self._visited_ids:
            # We have processed this node. We have either processed its
            # children or we are in middle of processing them.
            self.skip_children()
            return node

        if isinstance(node, CFGJump):
            return node
        if not isinstance(node, CFGNode):
            raise Exception('Unexpected')
        for block in node.insts:
            count_paths = len(block.cost_book.keys())
            exp = round(sum(block.cost_book.values()) / count_paths, 3)
            block.expected_cost = exp
        return node


def basic_block_cost_func(block, cfg_table):
    if len(block.insts) == 0:
        # Special case in which the block is empty
        return 0
    elif block.is_func_call():
        first_inst = block.insts[0]
        call_inst = _inst_is_func_call(first_inst)
        func_cfg = cfg_table.get(call_inst.name)
        assert func_cfg is not None
        return  basic_block_cost_func(func_cfg)
    elif block.is_red():
        cost = 0
        for inst in block.insts:
            tmp = consult_inst_cost_table(inst)
            cost += tmp
        return cost
    else:
        # Just original instructions
        return 0


def calculate_cost_along_path(path):
    acc = 0
    for block in path.blocks:
        cost = basic_block_cost_func(block)
        acc += cost
        block.cost_book[path.id] = acc


def analyse_offload(prog, info):
    # Transform the AST to a new AST which nodes are basic-blocks we want to
    # analyse
    cfg_table = {}
    cfg = create_basic_block_cfg(prog, info)
    cfg_table[...]

    # Extract all exection paths from the CFG. An execution path is a linear
    # sequence of basic blocks
    paths = extract_exec_paths(cfg, info)
    debug('Number of execution paths are:', len(paths), tag=MODULE_TAG)
    for path in paths:
        calculate_cost_along_path(path)

    # CalcExpectedCost.do(cfg, info)

    # SelectBoundaries.do(cfg, info)

    tmp = CFGGraphviz.do(cfg, info)
    tmp.dot.save('/tmp/cfg.dot')
    tmp.dot.render(filename='cfg', directory='/tmp/', format='svg')
