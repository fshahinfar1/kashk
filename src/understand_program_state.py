import clang.cindex as clang
from utility import find_elem


class StateObject:
    def __init__(self, name, type_name, kind):
        self.name = name
        self.type = type_name
        self.kind = kind

    def get_c_code(self):
        return f'{self.type} {self.name};'

    def __repr__(self):
        return f'<StateObject: {self.type} {self.name}>'


def extract_state(cursor):
    def __recursive(cursor):
        states = []
        for c in cursor.type.get_fields():
            if c.type.kind == clang.TypeKind.RECORD:
                states += __recursive(c)
            else:
                states.append(StateObject(c.spelling, c.type.spelling, c.type.kind))
        return states

    # Expect to store per connection state on this class
    conn = find_elem(cursor, 'TCPConnection')
    states = __recursive(conn)
    return states
