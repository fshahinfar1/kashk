import clang.cindex as clang


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


def parse_file(file_path):
    # compiler_args = '-I /usr/include/ -I /opt/clang-16/include/c++/v1/'.split()
    compiler_args = '-std=c++20'.split()
    index = clang.Index.create()
    tu = index.parse(file_path, args=compiler_args)
    print('---------------------------------------')
    print('Diagnostics:')
    print('---------------------------------------')
    for d in tu.diagnostics:
        print(d.format())
    print('---------------------------------------')
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
    struct = [f'struct {name} {{'] + [f.get_c_code() for f in fields] + ['};']
    return '\n'.join(struct)


def visualize_ast(cursor):
    """
    Print the clang AST for better understanding of its structure
    """
    q = [(cursor, 0)]
    # Outside the connection polling loop
    while q:
        c, l = q.pop()

        print('|  '*l + f'+- {c.spelling} {c.kind}')

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
    print(c.spelling, c.kind)
    children = list(c.get_children())
    print([(x.spelling, x.kind) for x in children])
    # DEBUGING: Show every line of code
    if c.location.file:
        fname = c.location.file.name
        with open(fname) as f:
            l = f.readlines()[c.location.line-1]
            l = l.rstrip()
            print(l)
            print(' ' * (c.location.column -1) + '^')


def show_insts(lst, depth=0):
    """
    Visualize the tree of instructions
    """
    for i in lst:
        print('  '*depth + str(i))
        # print(i.get_c_code())
        if i.has_children():
            show_insts(i.body, depth=depth+1)
            # print('  '*depth + '<OTHERWISE>')
            # __show_insts(i.other_body, depth=depth+1)
            # print('  '*depth + '<END>')

