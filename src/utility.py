import os
import clang.cindex as clang
import subprocess
import time

from log import error, debug, report
from passes.clone import clone_pass


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

def try_get_definition(cursor):
    if cursor.is_definition():
        return cursor
    tmp = cursor.get_definition()
    if tmp is None:
        return cursor
    return tmp


def implies(q, p):
    return not q or p


def parse_file(file_path, args):
    # compiler_args = '-I /usr/include/ -I /opt/clang-16/include/c++/v1/'.split()
    _, ext = os.path.splitext(file_path)
    curdir = os.path.abspath(os.path.dirname(__file__))
    args += f' -include {curdir}/headers/annotation.h'
    args += f' -include {curdir}/headers/my_bpf_headers/internal_types.h'
    if ext == '.c':
        # This is a C file
        compiler_args = (args + ' -DHAVE_CONFIG_H=1').split()
    else:
        # This is a C++ file
        compiler_args = (args + ' -std=c++20').split()
    report('Compiler args:', compiler_args)

    # Do preprocessing, the libclang is not doing well with macros
    tmp = ' '.join(compiler_args)
    use_pre_processing = False
    if use_pre_processing:
        cmd = f'clang -E {tmp} {file_path}'
        ts = int(time.time())
        prepfile = f'/tmp/kashk_preprocessed_file_{ts}' + ext
        with open(prepfile, 'w') as f:
            subprocess.run(cmd, shell=True, stdin=subprocess.DEVNULL, stdout=f)
    else:
        prepfile = file_path
    options = (
            clang.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD |
            clang.TranslationUnit.PARSE_INCLUDE_BRIEF_COMMENTS_IN_CODE_COMPLETION
            )
    options = clang.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    index = clang.Index.create()
    tu = index.parse(prepfile, args=compiler_args, options=options)
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
            m = list(filter(lambda c: c.spelling == name, cursor.get_children()))
            new_candid.extend(m)
        candid = new_candid
    if not candid:
        return None
    return candid


def find_elems_of_kind(cursor, kind, filter_fn=lambda e: True):
    matches = []
    if isinstance(cursor, list):
        for c in cursor:
            partial_res = find_elems_of_kind(c, kind, filter_fn)
            matches += partial_res
    else:
        if cursor.kind == kind and filter_fn(cursor):
            matches.append(cursor)
        for child in cursor.get_children():
            partial_res = find_elems_of_kind(child, kind, filter_fn)
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
    struct = f'struct {name} {{\n{body}\n}};'
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


def token_to_str(tkns):
    """
    Creates a string from the list of tokens
    """
    return ''.join(list(map(lambda t: t.spelling, tkns)))


def get_token_from_source_code(c):
    if c.location.file:
        # Do we know the source file?
        fname = c.location.file.name
        if os.path.isfile(fname):
            with open(fname) as f:
                l = f.readlines()[c.location.line-1]
                l = l.rstrip()
                token = l[c.location.column-1:]
                end_index = min(filter(lambda x: x > 0, [len(token) - 1, token.find(' '), token.find('\t'), token.find(';'), token.find(')'), token.find('}')]))
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
                lines = f.readlines()
                # debug(c.location.line-1, len(lines))
                # debug(c.location.file.name)
                assert c.location.line > 0 and c.location.line <= len(lines)
                l = lines[c.location.line-1]
                l = l.rstrip()
                debug(l)
                debug(' ' * (c.location.column -1) + '^')


def _get_owner(cursor):
    """
    @returns list of Instruction
    """
    from parser.understand_logic import gather_instructions_from
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
        res += _get_owner(parent)
    elif parent.kind == clang.CursorKind.PAREN_EXPR:
        first_child = next(parent.get_children())
        ref = gather_instructions_from(first_child, None)
        assert len(ref) == 1, f'{ref}'
        ref = ref[0]
        res.append(ref)
        if hasattr(ref, 'owner'):
            res = res + ref.owner
    else:
        error('_get_owner: unhandled cursor kind', parent.kind)
        report_on_cursor(cursor)
        report_on_cursor(parent)

    return res


def get_owner(cursor):
    tmp = _get_owner(cursor)
    if len(tmp) == 0:
        return tmp

    tmp = [clone_pass(x) for x in tmp]
    tmp.reverse()
    first = x = tmp.pop()
    while tmp:
        y = tmp.pop()
        x.owner = [y,]
        x.kind = clang.CursorKind.MEMBER_REF_EXPR
        x = y
    return [first,]


def get_actual_type(_T):
    """
    This method is for finding the object type in the case of having pointers
    of pointers or multi-dimensional arrays.
    """
    T = _T
    while True:
        if T.kind == clang.TypeKind.POINTER:
            T = T.get_pointee()
        elif T.kind == clang.TypeKind.CONSTANTARRAY:
            T = T.element_type
        else:
            break
    T = skip_typedef(T)
    return T


def get_top_owner(inst):
    x = inst
    while x.owner:
        x = x.owner[0]
    return x


INDENT='  '
def indent(text, count=1, indent=INDENT):
    """
    Indent a multiline string
    """
    body = text.split('\n')
    indented = []
    for b in body:
        if not b:
            continue
        indented.append(indent * count + b)
    body = '\n'.join(indented)
    return body


def filter_insts(block, filter_fn):
    """
    Select a set of instructions from a block of code based on a function
    filter_fn.
    """
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
    """
    The clang parser is generates some UNEXPOSED_STMT nodes in the AST.
    This function simply traverse children of these nodes until reaching to a
    node of other type.
    """
    ptr = cursor
    while (ptr.kind == clang.CursorKind.UNEXPOSED_STMT or
            ptr.kind == clang.CursorKind.UNEXPOSED_EXPR):
        children = list(ptr.get_children())
        assert len(children) == 1
        ptr = children[0]
    return ptr


def skip_typedef(T):
    tmp = T
    while tmp.kind == clang.TypeKind.TYPEDEF:
        tmp = tmp.under_type
    return tmp


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
        from code_gen import gen_code
        text, _ = gen_code(node.paths.code, info)
        debug(text)
        debug('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
        q.append(0)
        q.extend(reversed(node.children))


tmp_num = 100
def get_tmp_var_name():
    """
    This function is used to get a name for variables we need
    """
    global tmp_num
    name = f'_tmp_{tmp_num}'
    tmp_num += 1
    return name


def introduce_internal_struct(name, fields, info):
    from data_structure import Record
    rec = Record(name, fields)
    rec.update_symbol_table(info.sym_tbl)
