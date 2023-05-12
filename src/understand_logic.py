import clang.cindex as clang
from utility import get_code


class VarDecl:
    def __init__(self, c):
        self.cursor = c
        self.type = c.type.spelling
        self.name = c.spelling

    def get_c_code(self):
        return f'{self.type} {self.name};'

    def __repr__(self):
        return f'<VarDecl {self.type} {self.name}>'


def go_through_the_code(cursor):
    find_event_loop(cursor)

    outside_loop = True
    connection_state = []
    linear = []
    q = [cursor]
    # Outside the connection polling loop
    while q:
        c = q.pop()
        # What are we processing?
        print(c.spelling, c.kind)

        # DEBUGING: Show every line of code
        if c.location.file:
            fname = c.location.file.name
            with open(fname) as f:
                l = f.readlines()[c.location.line-1]
                l = l.rstrip()
                print(l)
                print(' ' * (c.location.column -1) + '^')

        if c.kind == clang.CursorKind.UNEXPOSED_EXPR:
            print(f'unknow expr')
            continue
        elif c.kind == clang.CursorKind.DECL_STMT:
            # Some declare statements are not declaring types or variables
            # (e.g., co_await, co_return, co_yield, ...)
            v = handle_declare_stmt(c)
            if v:
                connection_state.append(v)
            # We do not need to investigate the children of this node
            continue

        # print(get_code(c))

        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)
    print(connection_state)


def handle_declare_stmt(cursor):
    """
    If the cursor points to a variable decleration, then create the proper
    object for further code generation.
    """
    children = list(cursor.get_children())
    if len(children) != 1:
        print(children)
    if not children:
        return None
    var_decl = children[0]
    assert var_decl.kind == clang.CursorKind.VAR_DECL
    return VarDecl(var_decl)


def find_event_loop(cursor):
    q = [cursor]
    # Outside the connection polling loop
    while q:
        c = q.pop()
        # What are we processing?
        print(c.spelling, c.kind)

        if c.kind in (clang.CursorKind.WHILE_STMT, clang.CursorKind.DO_STMT,
                clang.CursorKind.FOR_STMT):
            # A loop found
            if __has_read(c):
                # This is the event loop
                return c
            

        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)


def __has_read(cursor):
    q = [cursor]
    # Outside the connection polling loop
    while q:
        c = q.pop()
        if c.kind == clang.CursorKind.CALL_EXPR:
            if c.spelling == 'async_read_some':
                return True


        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)
    return False
