from contextlib import contextmanager
from data_structure import Function
from code_gen import gen_code
from log import debug
from sym_table import Scope

from framework_support import InputOutputContext

from utility import parse_file
from parser.find_ev_loop import get_entry_code, find_event_loop
from parser.understand_logic_handler import __add_func_definition2
from instruction import * 

USER_EVENT_LOOP_ENTRY = '__user_event_loop_entry__'

MODULE_TAG = '[User Code]'


class Path:
    def __init__(self):
        # External variables that this path depend
        self.var_deps = set()
        # The scope coresponding to this path
        self.scope = Scope()
        # The scope which originally holded this path
        self.original_scope = Scope()
        # Function definition which holds this path
        self.func_obj = Function('__empty__', None, {})
        self.call_inst = []

    @property
    def code(self):
        return self.func_obj.body

    @code.setter
    def code(self, body):
        self.func_obj.body = body


class FallbackRegionGraph:
    def __init__(self):
        self.parent = None
        self.children = []
        # Codes associated with this node
        self.paths = Path()
        # Id of paths that cross this node
        self.path_ids = set()

        self.to_user_inst = None

    def append(self, code):
        """
        Associate a path of code with this node
        """
        path = Path()
        path.code = code
        self.paths = path
        return path

    def add_child(self, node):
        self.children.append(node)
        for i in node.path_ids:
            self.set_id(i)

    def is_empty(self):
        # return len(self.children) == 0 and len(self.paths) == 0
        return len(self.children) == 0 and not self.paths.code.has_children()

    def is_leaf(self):
        return len(self.children) == 0

    def remove(self):
        if self.parent:
            self.parent.remove_child(self)
            self.parent = None
        # TODO: what happens to the children?
        assert len(self.children) == 0
        self.paths = Path()

    def remove_child(self, child):
        self.children.remove(child)

    def new_child(self):
        cur = self
        node = FallbackRegionGraph()
        cur.add_child(node)
        node.parent = cur
        return node

    def set_id(self, i):
        self.path_ids.add(i)
        # traves up toward root and tag the nodes
        # debug('user graph node recieves id:', i, 'its parent is:', self.parent, tag=MODULE_TAG)
        if self.parent is not None:
            self.parent.set_id(i)

    def has_code(self):
        return self.paths is not None and self.paths.code.has_children()


class UserProg:
    """
    Hold the information needed for generating the userspace program
    """
    def __init__(self):
        # TODO: the graph could be a forest! I probably should use a list (I do
        # not remember what did this comment mean?)
        self.graph = FallbackRegionGraph()
        self.sym_tbl = None
        self.func_dir = None
        self.fallback_funcs_def = []
        self.declarations = {}

    @contextmanager
    def select_context(self, info):
        prev_sym_tbl = info.sym_tbl
        prev_func_dir = Function.directory
        info.sym_tbl = self.sym_tbl
        Function.directory = self.func_dir
        # Switch to the entry function scope
        user_old_scope = self.sym_tbl.current_scope
        entry_name = info.io_ctx.entry_func
        scope = info.sym_tbl.scope_mapping[entry_name]
        info.sym_tbl.current_scope = scope
        try:
            yield None
        finally:
            info.sym_tbl = prev_sym_tbl
            Function.directory = prev_func_dir
            self.sym_tbl.current_scope = user_old_scope

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


def _get_recv_func(meta, info):
    # TODO: these part has been hard-coded not because it is not possible to do
    # it right but becasue I think there are more important things to work on.
    if info.io_ctx.input_framework == InputOutputContext.INPUT_CPP_ASIO20:
        return f"""
struct {meta.name} *__m;
const size_t __size = sizeof(struct {meta.name});
char __buf[__size];
auto __b = asio::buffer(__buf, __size);
/* Receive message and check the return value */
try {{
  co_await conn->socket().async_read_some(__b, asio::use_awaitable);
}} catch (const std::system_error &error) {{
  if (error.code() != asio::error::eof && error.code() != asio::error::connection_reset) {{
    std::cerr << "Error: " << error.what() << std::endl;
  }}
  co_return;
}}
__m = (struct {meta.name} *)__buf;
"""
    elif info.io_ctx.input_framework in (InputOutputContext.INPUT_C_EPOLL, InputOutputContext.INPUT_C_LIBEVENT):
        return f"""
struct {meta.name} *__m;
const size_t __size = sizeof(struct {meta.name}) + 1;
char __b[__size];
int __len = read(sockfd, __b, __size);
if (__len <= 0) {{
  fprintf(stderr, "Error reading from socket.\\n");
  close(sockfd);
  return;
}}
__b[__len] = '\\0';
__m = (struct {meta.name} *)__b;
"""
    else:
        debug('Framework:', info.io_ctx.input_framework)
        raise Exception(MODULE_TAG, 'Unexpected IO Framework!')


def _load_meta(info):
    # TODO: load the correct data structure based on the failure number
    # debug('--', info.user_prog.declarations, tag=MODULE_TAG)
    list_meta = list(info.user_prog.declarations.values())
    if len(list_meta) == 0:
        return ''
    meta = list_meta[0]
    declare = []
    load = []
    for f in meta.fields:
        declare.append(f.get_c_code())
        load.append(f'{f.name} = __m->{f.name};')
    recv_pkt = _get_recv_func(meta, info)
    declare = '\n'.join(declare)
    load = '\n'.join(load)
    return declare + '\n' + recv_pkt + '\n' + load


def generate_user_prog(main, info):
    """
    Generate the final userspace program
    """
    assert isinstance(main, Block)
    code = []
    sym_tbl = info.sym_tbl

    # New type declarations
    declarations, _ = gen_code(list(info.user_prog.declarations.values()), info)
    code.append(declarations)
    code.append('\n')

    # New function definitions
    funcs = list(reversed(info.user_prog.fallback_funcs_def))
    func_text, _ = gen_code(funcs, info)
    code.append(func_text)

    # Load the meta-data from the packet first thing in the event loop
    tmp = _load_meta(info)
    meta_load_inst = Literal(tmp, CODE_LITERAL)
    main.children.insert(0, meta_load_inst)

    # Find the entry function again and replace the event loop
    index, tu, cursor = parse_file(info.io_ctx.input_file, info.io_ctx.cflags)
    _, entry_func = get_entry_code(cursor, info)
    gs = sym_tbl.sk_state_scope
    with sym_tbl.with_scope(gs):
        f = __add_func_definition2(USER_EVENT_LOOP_ENTRY, entry_func, info)
        f.update_symbol_table(sym_tbl)
    ev_loop = find_event_loop(f.body)
    if ev_loop is None:
        ev_loop = f
    ev_loop.body = main
    # Generate the textual code
    text, _ = gen_code([f,], info)
    code.append(text)
    return '\n'.join(code)
