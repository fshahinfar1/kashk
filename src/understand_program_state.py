import clang.cindex as clang
from utility import find_elem, get_code, generate_struct_with_fields


class StateObject:
    def __init__(self, c):
        self.cursor = c
        self.name = c.spelling
        self.type = c.type.spelling 
        self.kind = c.type.kind

    def get_c_code(self):
        return f'{self.type} {self.name};'

    def __repr__(self):
        return f'<StateObject: {self.type} {self.name}>'


def generate_decleration_for(cursor):
    """
    cursor is a class, struct, enum, ...
    return a list of strings having codes for defining the types needed.
    """
    type_name = cursor.spelling
    # List of type dependencies for this specific type
    decl = []
    if cursor.type.kind == clang.TypeKind.RECORD:
        # Go through the fields, add any dependencies field might have, then
        # define a struct for it.
        fields, new_decl = __extract_state(cursor)
        decl += new_decl
        new_struct = generate_struct_with_fields(type_name, fields)
        decl.append(new_struct)
    else:
        # For enum, union, typedef
        c = cursor.type.get_declaration()
        d = get_code(c) + ';'
        decl.append(d)

    return decl

def __extract_state(cursor):
    states = []
    decl = []
    for c in cursor.type.get_fields():
        if c.type.kind in (clang.TypeKind.RECORD, clang.TypeKind.ELABORATED):
            d = generate_decleration_for(c)
            decl += d
        states.append(StateObject(c))
    return states, decl

def extract_state(cursor):
    # Expect to store per connection state on this class
    conn = find_elem(cursor, 'TCPConnection')
    states, decls = __extract_state(conn)
    return states, decls
