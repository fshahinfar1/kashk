import os
import clang.cindex as clang
import subprocess

from log import error, debug, report


PRIMITIVE_TYPES = [
clang.TypeKind.BOOL,
clang.TypeKind.CHAR_U,
clang.TypeKind.UCHAR,
clang.TypeKind.CHAR16,
clang.TypeKind.CHAR32,
clang.TypeKind.USHORT,
clang.TypeKind.UINT,
clang.TypeKind.ULONG,
clang.TypeKind.ULONGLONG,
clang.TypeKind.UINT128,
clang.TypeKind.CHAR_S,
clang.TypeKind.SCHAR,
clang.TypeKind.WCHAR,
clang.TypeKind.SHORT,
clang.TypeKind.INT,
clang.TypeKind.LONG,
clang.TypeKind.LONGLONG,
clang.TypeKind.INT128,
clang.TypeKind.FLOAT,
clang.TypeKind.DOUBLE,
clang.TypeKind.LONGDOUBLE,
clang.TypeKind.VOID,
]

def implies(q, p):
    return not q or p


def get_body_of_the_loop(cursor):
    body_of_loop = None
    for child in cursor.get_children():
        if child.kind == clang.CursorKind.COMPOUND_STMT:
            body_of_loop = child
            break
    return body_of_loop


def parse_file(file_path, args):
    # compiler_args = '-I /usr/include/ -I /opt/clang-16/include/c++/v1/'.split()
    _, ext = os.path.splitext(file_path)
    curdir = os.path.abspath(os.path.dirname(__file__))
    args += f' -include {curdir}/headers/annotation.h'
    if ext == '.c':
        # This is a C file
        compiler_args = (args + ' -DHAVE_CONFIG_H=1').split()
    else:
        # THis is a C++ file
        compiler_args = (args + ' -std=c++20').split()
    report('Compiler args:', compiler_args)

    # Do preprocessing, the libclang is not doing well with macros
    tmp = ' '.join(compiler_args)
    # cmd = f'clang -E {tmp} {file_path}'
    # prepfile = '/tmp/kashk_preprocessed_file' + ext
    # with open(prepfile, 'w') as f:
    #     subprocess.run(cmd, shell=True, stdin=subprocess.DEVNULL, stdout=f)
    prepfile = file_path
    index = clang.Index.create()
    tu = index.parse(prepfile, args=compiler_args)
    if tu.diagnostics:
        error('Diagnostics:')
        for d in tu.diagnostics:
            error(d.format())
    cursor = tu.cursor
    return index, tu, cursor


def find_elem(cursor, func_name):
    """
    Find a AST node with matching name
    """
    candid = [cursor]
    h = func_name.split('::')
    for name in h:
        new_candid = []
        for cursor in candid:
            match = list(filter(lambda c: c.spelling == name, cursor.get_children()))
            new_candid.extend(match)
        candid = new_candid
    if not candid:
        return None
    return candid


def find_elems_of_kind(cursor, kind):
    matches = []
    if isinstance(cursor, list):
        for c in cursor:
            partial_res = find_elems_of_kind(c, kind)
            matches += partial_res
    else:
        if cursor.kind == kind:
            matches.append(cursor)
        for child in cursor.get_children():
            partial_res = find_elems_of_kind(child, kind)
            matches += partial_res
    return matches


def get_code(cursor):
    """
    Convert a cursor to a line of code (naively)
    """
    text = ''
    indent = 0
    new_line = False
    for c in cursor.get_tokens():
        x = c.spelling

        if x == '{':
            indent += 1
        elif x == '}':
            indent -= 1

        if new_line:
            text +=  '  ' * indent
            new_line = False

        text += x
        text += ' '

        if x in (';', '{', '}') or x.startswith('/*') or x.startswith('//'):
            text += '\n'
            new_line = True
    return text


def generate_struct_with_fields(name, fields):
    """
    Create a struct definition with the given name and fields.
    fields: an array of type StateObject
    """
    body = indent('\n'.join([f.get_c_code() for f in fields]), 1)
    struct = f'struct {name} {{\n' + body + '\n}'
    return struct


def visualize_ast(cursor):
    """
    Print the clang AST for better understanding of its structure
    """
    q = [(cursor, 0)]
    # Outside the connection polling loop
    while q:
        c, l = q.pop()

        debug('|  '*l + f'+- {c.spelling} {c.kind}')

        # Continue deeper
        children = list(reversed(list(c.get_children())))
        for child in children:
            q.append((child, l+1))


def get_token_from_source_code(c):
    if c.location.file:
        # Do we know the source file?
        fname = c.location.file.name
        if os.path.isfile(fname):
            with open(fname) as f:
                l = f.readlines()[c.location.line-1]
                l = l.rstrip()
                token = l[c.location.column-1:]
                end_index = min(filter(lambda x: x > 0, [token.find(' '), token.find('\t'), token.find(';'), token.find(')'), token.find('}')]))
                token = token[:end_index]
                return token
    return '<token not found>'


def report_on_cursor(c):
    """
    print some information about the cursor:
        1. Name and its kind
        2. List of its children
        3. Line of code in the source file
    """
    # What are we processing?
    debug(c.spelling, c.kind)
    children = list(c.get_children())
    debug([(x.spelling, x.kind) for x in children])
    # DEBUGING: Show every line of code
    if c.location.file:
        fname = c.location.file.name
        if os.path.isfile(fname):
            with open(fname) as f:
                l = f.readlines()[c.location.line-1]
                l = l.rstrip()
                debug(l)
                debug(' ' * (c.location.column -1) + '^')


def show_insts(lst, depth=0):
    """
    Visualize the tree of instructions
    """
    from instruction import Block
    indent = '  '
    if isinstance(lst, Block):
        lst = lst.children
    for i in lst:
        debug(indent * depth + str(i))
        if isinstance(i, list):
            show_insts(i, depth=depth+1)
        elif i.has_children():
            show_insts(i.get_children(), depth=depth+1)


def get_owner(cursor):
    """
    @returns list of Instruction
    """
    from understand_logic import gather_instructions_from
    res = []
    children = list(cursor.get_children())
    if len(children) == 0:
        return []
    parent = children[0]
    if parent.kind in (clang.CursorKind.DECL_REF_EXPR,
            clang.CursorKind.MEMBER_REF_EXPR,
            clang.CursorKind.ARRAY_SUBSCRIPT_EXPR,
            clang.CursorKind.CALL_EXPR,):
        ref = gather_instructions_from(parent, None)
        assert len(ref) == 1, f'{ref}'
        ref = ref[0]
        res.append(ref)
        if hasattr(ref, 'owner'):
            res = res + ref.owner
    elif parent.kind == clang.CursorKind.UNEXPOSED_EXPR:
        res += get_owner(parent)
    elif parent.kind == clang.CursorKind.PAREN_EXPR:
        first_child = next(parent.get_children())
        ref = gather_instructions_from(first_child, None)
        assert len(ref) == 1, f'{ref}'
        ref = ref[0]
        res.append(ref)
        if hasattr(ref, 'owner'):
            res = res + ref.owner
    else:
        error('get_owner: unhandled cursor kind', parent.kind)
        report_on_cursor(cursor)
        report_on_cursor(parent)

    return res


"""
This method is for finding the object type in the case of having pointers of
pointers or multi-dimensional arrays.
"""
def get_actual_type(_T):
    T = _T
    while True:
        if T.kind == clang.TypeKind.POINTER:
            T = T.get_pointee()
        elif T.kind == clang.TypeKind.CONSTANTARRAY:
            T = T.element_type
        else:
            break
    return T


INDENT = '  '
def indent(text, count=1):
    body = text.split('\n')
    indented = []
    for b in body:
        if not b:
            continue
        indented.append(INDENT * count + b)
    body = '\n'.join(indented)
    return body


def filter_insts(block, filter_fn):
    result = []
    q = [block]
    # Outside the connection polling loop
    while q:
        c = q.pop()
        if filter_fn(c):
            result.append(c)
            continue

        # Continue deeper
        for child in reversed(c.get_children()):
            q.append(child)
    return result


def skip_unexposed_stmt(cursor):
    ptr = cursor
    while (ptr.kind == clang.CursorKind.UNEXPOSED_STMT or
            ptr.kind == clang.CursorKind.UNEXPOSED_EXPR):
        children = list(ptr.get_children())
        assert len(children) == 1
        ptr = children[0]
    return ptr


def add_state_decl_to_bpf(prog, states, decls):
    for s in states:
        prog.add_connection_state(s)
    for d in decls:
        prog.add_declaration(d)


def draw_tree(root, fn=lambda x: str(len(x.children))):
    delimeter = ' '
    v_space = 2
    h_space = 4

    # count_children = len(root.children)
    number_of_lines = 0
    sub_trees = []
    for child in root.children:
        sub_tree = draw_tree(child, fn=fn)
        lines = list(filter(lambda x: bool(x), sub_tree.split('\n')))
        height = len(lines)
        width = max([len(l) for l in lines])
        sub_trees.append((lines, width))
        number_of_lines = max(number_of_lines, height)

    width = 0
    below = []
    for l in range(number_of_lines):
        line = ''
        for sub_tree, width in sub_trees:
            if len(sub_tree) > l:
                line = line + sub_tree[l] + (delimeter * h_space)
            else:
                line = line + ' ' * width + (delimeter * h_space)
        below.append(line)
        width = max(width, len(line))
    below = ('\n' * v_space).join(below)
    node = f'[{fn(root)}]'
    space_needed = width - len(node)
    left_space = space_needed // 2
    right_space = space_needed - left_space
    node = (' ' * left_space) + node + (' ' * right_space) + '\n'
    result = node + ('\n' * v_space) + below
    return result


def report_user_program_graph(info):
    root = info.user_prog.graph
    s = draw_tree(root)
    debug(s, '\n')

    q = [0, info.user_prog.graph]
    lvl = 0
    while q:
        node = q.pop()
        if node == 0:
            lvl += 1
            continue
        debug('lvl:', lvl, 'children:', len(node.children), []) # node.paths.code.children
        q.append(0)
        q.extend(reversed(node.children))

    # Look at the status
    q = [0, info.user_prog.graph]
    lvl = 0
    while q:
        node = q.pop()
        if node == 0:
            lvl += 1
            continue
        debug('lvl:', lvl, node.path_ids)
        debug(node.paths.var_deps)
        from bpf_code_gen import gen_code
        text, _ = gen_code(node.paths.code, info)
        debug(text)
        debug('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
        q.append(0)
        q.extend(reversed(node.children))
