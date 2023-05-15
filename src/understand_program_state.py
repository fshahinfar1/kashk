import sys
import clang.cindex as clang
from utility import find_elem, get_code, generate_struct_with_fields, PRIMITIVE_TYPES


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


class TypeDefinition:
    def __init__(self, name):
        self.name = name

    def __hash__(self):
        return self.name.__hash__()

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.name == other.name
        return False

    def get_c_code(self):
        raise Exception('Not implemented')


class Elaborate(TypeDefinition):
    directory = {}

    def __init__(self, c):
        super().__init__(c.spelling)
        self.cursor = c
        if self.name in Elaborate.directory:
            raise Exception('Unexpected error')
        Elaborate.directory[self.name] = self

    def get_c_code(self):
        d = get_code(self.cursor) + ';'
        return d


class Record(TypeDefinition):
    directory = {}

    def __init__(self, name, fields):
        super().__init__(name)
        self.fields = fields
        if self.name in Record.directory:
            raise Exception('Unexpected error')
        Record.directory[self.name] = self

    def get_c_code(self):
        return generate_struct_with_fields(self.name, self.fields)


def generate_decleration_for(cursor):
    """
    cursor is a class, struct, enum, ...
    return a list of strings having codes for defining the types needed.
    """
    # print('*', cursor.spelling, cursor.kind, cursor.type.kind)
    type_name = cursor.spelling

    # List of type dependencies for this specific type
    decl = []

    if cursor.type.kind == clang.TypeKind.RECORD:
        # Go through the fields, add any dependencies field might have, then
        # define a struct for it.
        fields, new_decl = extract_state(cursor)
        decl += new_decl
        r = Record(type_name, fields)
        decl.append(r)
    elif cursor.type.kind == clang.TypeKind.ELABORATED:
        # For enum, union, typedef
        c = cursor.type.get_declaration()
        d = generate_decleration_for(c)
        decl.extend(d)
        decl.append(Elaborate(c))
    elif cursor.type.kind == clang.TypeKind.ENUM:
        # No further deps
        return []
    elif cursor.type.kind == clang.TypeKind.TYPEDEF:
        if cursor.kind.is_declaration():
            t = cursor.underlying_typedef_type
            under_kind = t.kind
        else:
            print('Typedef if not declaration, I do not udnerstand this.')
            under_kind = cursor.kind
            # print('--', under_kind)
        if under_kind in PRIMITIVE_TYPES:
            # No further type decleration needed
            return []
        # print([(c.spelling, c.kind) for c in cursor.get_children()])
        for c in cursor.get_children():
            decl += generate_decleration_for(c)
    else:
        print('Unexpected! ' + str(cursor.type.kind), file=sys.stderr)

    return decl


def extract_state(cursor):
    """
    Extract fields and dependant type declartion from a class or struct
    """
    states = []
    decl = []
    for c in cursor.type.get_fields():
        if c.type.kind in (clang.TypeKind.RECORD, clang.TypeKind.ELABORATED):
            d = generate_decleration_for(c)
            decl += d
        states.append(StateObject(c))
    return states, decl


def get_state_for(cursor):
    """
    Get state definition and needed decleration for a variable or parameter
    declartion
    """
    states = []
    decl = []
    k = cursor.kind
    if k == clang.CursorKind.PARM_DECL:
        states.append(StateObject(cursor))
        decl = generate_decleration_for(cursor) 
    elif k == clang.CursorKind.VAR_DECL:
        states.append(StateObject(cursor))
        decl = generate_decleration_for(cursor)
    else:
        raise Exception('Not implemented! ' + str(k))
    return states, decl

