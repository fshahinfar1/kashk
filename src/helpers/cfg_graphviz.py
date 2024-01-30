"""
This module provides helper functions for visualizing the CFG.
"""
import os
import re
import graphviz

from log import debug
from code_pass import Pass
from code_gen import gen_code
from cfg import CFGNode, CFGJump
from brain.basic_block import BasicBlock


MODULE_TAG = '[CFG Graphviz]'


shape_config = {
        CFGNode: 'rect',
        BasicBlock: 'rect',
        CFGJump: 'diamond',
}


def code_format(s):
    chunk_size = 25
    tmp = s.strip()
    length = len(tmp)
    remainder = 0 if length % chunk_size == 0 else 1
    num_chunk = (length // chunk_size) + remainder
    c = [tmp[i * chunk_size:(i + 1) * chunk_size] for i in range(num_chunk)]
    res = '\n '.join(c)
    return res


class CFGGraphviz(Pass):
    def __init__(self, info, comment=None):
        super().__init__(info)
        self.dot = graphviz.Digraph(comment=comment,
                node_attr={
                    'style':'filled',
                    'color':'white',
                    'stroke': 'black',
                    'fontname': 'monospace',
                    },
                )

    def get_cfg_node_label(self, node):
        if isinstance(node, CFGNode):
            insts = [gen_code([i], self.info)[0] for i in node.insts]
            insts = map(code_format, insts)
            lbl = '\n'.join(insts)
            if isinstance(node, BasicBlock):
                lbl += f'\nexp_cost: {node.expected_cost}'
            return lbl
        elif isinstance(node, CFGJump):
            cond_text, _ = gen_code([node.cond,], self.info)
            return cond_text
        raise Exception('Unexpected')

    def process_current_inst(self, node, more):
        if node.node_id in self._visited_ids:
            self.skip_children()
            return node
        NID = node.node_id
        shape = shape_config[type(node)]
        color = 'silver'
        if isinstance(node, CFGNode):
            if len(node.insts) > 0 and isinstance(node, BasicBlock):
                if node.is_func_call():
                    color = 'lightgreen'
                elif node.is_red():
                    color = 'lightcoral'
                else:
                    color = 'lightblue2'
            lbl = self.get_cfg_node_label(node)
            self.dot.node(NID, label=lbl, shape=shape, color=color)
            if node.next is not None:
                T_NID = node.next.node_id
                self.dot.edge(NID, T_NID)
        elif isinstance(node, CFGJump):
            lbl = self.get_cfg_node_label(node)
            self.dot.node(NID, label=lbl, shape=shape, color=color)
            for case_cond, target_node in node.jmps:
                T_NID = target_node.node_id
                edge_lbl, _ = gen_code([case_cond,], self.info)
                self.dot.edge(NID, T_NID, label=edge_lbl)
        else:
            raise Exception('Unexpected')
        return node
