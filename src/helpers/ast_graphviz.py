"""
This module provides helper functions for generating .dot file (graphs).
"""
import os
import re
import graphviz

from log import debug
from code_pass import Pass
from code_gen import gen_code


MODULE_TAG = '[AST Graphviz]'


class ASTGraphviz(Pass):
    def __init__(self, info, comment=None):
        super().__init__(info)
        self.dot = graphviz.Digraph(comment=comment)
        self._counter = 0

        root_id = self._new_node('-')
        self.last_node = [root_id,]

    def _new_node(self, label):
        self._counter += 1
        NID = f'N{self._counter}'
        self.dot.node(NID, label=label)
        return NID

    def _next_node(self, label, is_parent):
        node_id = self._new_node(label)
        parent = self.last_node[-1]
        if parent is not None:
            self.dot.edge(parent, node_id)
        if is_parent:
            self.last_node.append(node_id)

    def process_current_inst(self, inst, more):
        lbl = str(inst)
        lbl = f'"{lbl}"'
        has_children = inst.has_children()
        self._next_node(lbl, has_children)
        return inst

    def end_current_inst(self, inst, more):
        if inst.has_children():
            self.last_node.pop()
        return inst

    def save_file(self, file):
        if os.path.isfile(file):
            debug('File already exists', tag=MODULE_TAG)
        self.dot.save(file)
