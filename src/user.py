from contextlib import contextmanager
from data_structure import Function
from bpf_code_gen import gen_code
from log import debug


class Graph:
    def __init__(self):
        self.parent = None
        # Other nodes of control graph
        self.children = [] # TODO: maybe use a set?
        # Codes associated with this node
        self.paths = []

    def append(self, child):
        self.paths.append(child)

    def add_child(self, node):
        self.children.append(node)

    def is_empty(self):
        return len(self.children) == 0 and len(self.paths) == 0

    def remove(self):
        if self.parent:
            self.parent.remove_child(self)
            self.parent = None

        # TODO: what happens to the children?
        assert len(self.children) == 0

        self.paths.clear()

    def remove_child(self, child):
        self.children.remove(child)

    def new_child(self):
        cur = self
        node = Graph()
        cur.add_child(node)
        node.parent = cur
        return node


class UserProg:
    def __init__(self):
        self.graph = Graph()
        self.sym_tbl = None
        self.func_dir = None

    @contextmanager
    def select_context(self, info):
        prev_sym_tbl = info.sym_tbl
        prev_func_dir = Function.directory
        info.sym_tbl = self.sym_tbl
        Function.directory = self.func_dir
        try:
            yield None
        finally:
            info.sym_tbl = prev_sym_tbl
            Function.directory = prev_func_dir


    def insert_super_node(self):
        cur = self.graph
        node = Graph()
        node.add_child(cur)
        cur.parent = node
        self.graph = node
        return node

    def insert_sub_node(self):
        cur = self.graph
        node = Graph()
        cur.add_child(node)
        node.parent = cur
        return node

    def show(self, info):
        q = [(self.graph, 0)]
        while q:
            g, lvl = q.pop()
            
            debug('level:', lvl)
            for p in g.paths:
                text, _ = gen_code(p, info)
                debug(text)
                debug('----')

            next_lvl = lvl + 1
            for c in reversed(g.children):
                q.append((c, next_lvl))
