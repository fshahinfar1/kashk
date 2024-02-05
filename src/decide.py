"""
Decide what part of the user program to offload
"""
from math import inf

from cfg import CFGJump, CFGNode, cfg_leafs
from code_pass import Pass
from data_structure import Function
from log import debug
from brain.basic_block import BasicBlock, create_basic_block_cfg
from brain.exec_path import extract_exec_paths
from brain.cost_func import calculate_cost_along_path, CalcExpectedCost
from helpers.cfg_graphviz import CFGGraphviz
from helpers.function_call_dependency import find_function_call_dependencies


MAIN = '__main__'
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
        elif isinstance(node, BasicBlock):
            if node.expected_cost < self.cur_min:
                self.cur_sel = node
                self.cur_min = node.expected_cost
        return node

    def end_current_inst(self, node, more):
        if node == self.entry_node:
            # we are exiting the evaluation of the root
            # What was the choice?
            tmp = (self.cur_sel, self.cur_min)
            self.selected_blocks.append(tmp)
            # END


def analyse_offload(prog, info):
    cfg_table = {}
    relevant_func_names = set(func.name
            for func in Function.directory.values()
                if func.is_used_in_bpf_code)
    # Find function call dependencies
    ordered_list_of_funcs = find_function_call_dependencies(relevant_func_names)
    debug('order of evaluating cost of functions:', ordered_list_of_funcs, tag=MODULE_TAG)
    cost_table = {}
    for name in ordered_list_of_funcs:
        debug('For func', name, tag=MODULE_TAG)
        func = Function.directory[name]
        cfg = create_basic_block_cfg(func.body, info)
        cfg_table[name] = cfg
        paths = extract_exec_paths(cfg, info)
        for path in paths:
            calculate_cost_along_path(path, cost_table)
        leafs = cfg_leafs(cfg)
        exp_cost_func = 0
        count_path = 0
        for l in leafs:
            count_path += len(l.cost_book.keys())
            exp_cost_func += sum(l.cost_book.values())
        exp_cost_func = round(exp_cost_func / count_path, 3)
        cost_table[name] = exp_cost_func
        debug('Add', name, 'with cost:', exp_cost_func, 'to the table',
                tag=MODULE_TAG)
        CalcExpectedCost.do(cfg, info)

    cfg = create_basic_block_cfg(prog, info)
    cfg_table[MAIN] = cfg
    paths = extract_exec_paths(cfg, info)
    for path in paths:
        calculate_cost_along_path(path, cost_table)
    CalcExpectedCost.do(cfg, info)
    # SelectBoundaries.do(cfg, info)

    tmp = CFGGraphviz.do(cfg, info)
    tmp.dot.save('/tmp/cfg.dot')
    tmp.dot.render(filename='cfg', directory='/tmp/', format='svg')
    for name, tmp_cfg in cfg_table.items():
        tmp = CFGGraphviz.do(tmp_cfg, info)
        tmp.dot.save(f'/tmp/cfg_{name}.dot')
        tmp.dot.render(filename=f'cfg_{name}', directory='/tmp/', format='svg')

