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

    # def add_path(self, inst):
    #     """
    #     @param inst: expect it to be a `Block' of code.
    #     """
    #     path = UserPath(inst)
    #     self.graph.append(path)
    #     return path

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


# class UserPath:
#     _path_number_gen = 0

#     def __init__(self, inst):
#         self.number = UserPath._path_number_gen
#         UserPath._path_number_gen += 1

#         self.body = inst

#         # TODO: how am I going to implement this?
#         self.states_it_need = []
