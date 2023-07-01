from contextlib import contextmanager
from data_structure import Function
from bpf_code_gen import gen_code
from log import debug

USER_EVENT_LOOP_ENTRY = '__user_event_loop_entry__'


class Path:
    def __init__(self):
        # The code this path should execute
        self.code = None
        # External variables that this path depend
        self.var_deps = set()
        # The scope coresponding to this path
        self.scope = None
        # The scope which originally holded this path
        self.original_scope = None
        # Function definition which holds this path
        self.func_obj = None
        self.call_inst = None


class FallbackRegionGraph:
    def __init__(self):
        self.parent = None
        # Other nodes of control graph
        # TODO: maybe use a set?
        self.children = []
        # Codes associated with this node
        # self.paths = []
        self.paths = None
        # Id of paths that cross this node
        self.path_ids = []

    def append(self, code):
        """
        Associate a path of code with this node
        """
        assert self.paths is None
        path = Path()
        path.code = code
        # self.paths.append(path)
        self.paths = path
        return path

    def add_child(self, node):
        self.children.append(node)

    def is_empty(self):
        # return len(self.children) == 0 and len(self.paths) == 0
        return len(self.children) == 0 and self.paths is None

    def is_leaf(self):
        return len(self.children) == 0

    def remove(self):
        if self.parent:
            self.parent.remove_child(self)
            self.parent = None

        # TODO: what happens to the children?
        assert len(self.children) == 0

        # self.paths.clear()
        self.paths = None

    def remove_child(self, child):
        self.children.remove(child)

    def new_child(self):
        cur = self
        node = FallbackRegionGraph()
        cur.add_child(node)
        node.parent = cur
        return node

    def set_id(self, i):
        self.path_ids.append(i)
        # traves up toward root and tag the nodes
        if self.parent is not None:
            self.parent.set_id(i)

    def has_code(self):
        return self.paths is not None and self.paths.code is not None


class UserProg:
    """
    Hold the information needed for generating the userspace program
    """
    def __init__(self):
        # TODO: the graph could be a forest! I probably should use a list
        self.graph = FallbackRegionGraph()
        self.sym_tbl = None
        self.func_dir = None
        self.entry_body = None
        self.fallback_funcs_def = []
        self.declarations = []

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
        node = FallbackRegionGraph()
        node.add_child(cur)
        cur.parent = node
        self.graph = node
        return node

    def insert_sub_node(self):
        cur = self.graph
        node = FallbackRegionGraph()
        cur.add_child(node)
        node.parent = cur
        return node

    def show(self, info):
        q = [(self.graph, 0)]
        while q:
            g, lvl = q.pop()

            debug('level:', lvl)
            # for p in g.paths:
            p = g.paths
            text, _ = gen_code(p, info)
            debug(text)
            debug('----')

            next_lvl = lvl + 1
            for c in reversed(g.children):
                q.append((c, next_lvl))


def generate_user_prog(info):
    """
    Generate the final userspace program
    """
    code = []

    declarations, _ = gen_code(info.user_prog.declarations, info)
    code.append(declarations)
    code.append('\n')

    func_text, _ = gen_code(info.user_prog.fallback_funcs_def, info)
    code.append(func_text)

    entry_body, _ = gen_code(info.user_prog.entry_body, info)
    code.append(entry_body)

    return '\n'.join(code)
