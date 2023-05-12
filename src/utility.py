import clang.cindex as clang


def parse_file(file_path):
    compiler_args= ''
    index = clang.Index.create()
    tu = index.parse(file_path, args=compiler_args)
    cursor = tu.cursor
    return cursor


def find_elem(cursor, func_name):
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
