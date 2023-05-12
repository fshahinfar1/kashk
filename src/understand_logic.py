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


def get_variable_declaration_before_elem(cursor, target_cursor):
    variables = []
    q = [cursor]
    while q:
        c = q.pop()
        # # What are we processing?
        # print(c.spelling, c.kind)

        # # DEBUGING: Show every line of code
        # if c.location.file:
        #     fname = c.location.file.name
        #     with open(fname) as f:
        #         l = f.readlines()[c.location.line-1]
        #         l = l.rstrip()
        #         print(l)
        #         print(' ' * (c.location.column -1) + '^')

        if c == target_cursor:
            # Found the target element
            break

        if c.kind == clang.CursorKind.DECL_STMT:
            # Some declare statements are not declaring types or variables
            # (e.g., co_await, co_return, co_yield, ...)
            v = handle_declare_stmt(c)
            if v:
                variables.append(v)
            # We do not need to investigate the children of this node
            continue

        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)
    return variables


def handle_declare_stmt(cursor):
    """
    If the cursor points to a variable decleration, then create the proper
    object for further code generation.
    """
    children = list(cursor.get_children())
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
        # print(c.spelling, c.kind)

        if c.kind in (clang.CursorKind.WHILE_STMT, clang.CursorKind.DO_STMT,
                clang.CursorKind.FOR_STMT):
            # A loop found
            if __has_read(c):
                # This is the event loop
                return c
            

        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)
    return None


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
