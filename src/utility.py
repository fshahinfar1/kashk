import os
import clang.cindex as clang

from log import error, debug


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
]


def get_body_of_the_loop(cursor):
    body_of_loop = None
    for child in cursor.get_children():
        if child.kind == clang.CursorKind.COMPOUND_STMT:
            body_of_loop = child
            break
    return body_of_loop

def parse_file(file_path):
    # compiler_args = '-I /usr/include/ -I /opt/clang-16/include/c++/v1/'.split()
    compiler_args = '-std=c++20'.split()
    index = clang.Index.create()
    tu = index.parse(file_path, args=compiler_args)
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
    return candid[0]


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
    indent = '  '
    for i in lst:
        debug(indent * depth + str(i))
        if isinstance(i, list):
            show_insts(i, depth=depth+1)
        elif i.has_children():
            show_insts(i.get_children(), depth=depth+1)


def get_owner(cursor):
    res = []
    children = list(cursor.get_children())
    if len(children) == 0:
        return []
    parent = children[0]
    if parent.kind == clang.CursorKind.DECL_REF_EXPR: 
        res.append(parent.spelling)
    elif parent.kind == clang.CursorKind.MEMBER_REF_EXPR:
        res.append(parent.spelling)
        res += get_owner(parent)
    elif parent.kind == clang.CursorKind.CALL_EXPR:
        res += get_owner(parent)
    elif parent.kind == clang.CursorKind.UNEXPOSED_EXPR:
        res += get_owner(parent)
    else:
        error('get_owner: unhandled cursor kind')

    return res


def owner_to_ref(owner, info):
    owner = reversed(owner)
    hierarchy = []
    scope = info.sym_tbl.current_scope
    obj = None
    for x in owner:
        obj = scope.lookup(x)
        if obj is None:
            debug('did not found obj:', x)
            break
        hierarchy.append(obj)
        if obj.type.kind == clang.TypeKind.POINTER and obj.type.get_pointee():
            obj_cls = obj.type.get_pointee().spelling
        else:
            obj_cls = obj.type.spelling
        key = f'class_{obj_cls}'
        scope = info.sym_tbl.scope_mapping.get(key)
        if not scope:
            debug(f'scope not found for: |{key}|') 
            break
    return hierarchy


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
        # assert len(children) == 1
        ptr = children[0]
    return ptr


def add_state_decl_to_bpf(prog, states, decls):
    for s in states:
        prog.add_connection_state(s)
    for d in decls:
        prog.add_declaration(d)
