import clang.cindex as clang

from log import error, debug, report
from utility import skip_unexposed_stmt, report_on_cursor, find_elem
from sym_table import SymbolTableEntry
from dfs import DFSPass
from prune import READ_PACKET


def __has_read(cursor):
    q = [cursor]
    # Outside the connection polling loop
    while q:
        c = q.pop()
        if c.kind == clang.CursorKind.CALL_EXPR:
            if c.spelling in READ_PACKET:
                return True


        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)
    return False


def find_event_loop(cursor):
    d = DFSPass(cursor)
    for c, _ in d:
        if c.kind in (clang.CursorKind.WHILE_STMT, clang.CursorKind.DO_STMT,
                clang.CursorKind.FOR_STMT):
            # A loop found
            if __has_read(c):
                # This is the event loop
                return c
        d.go_deep()
    return None


def find_request_processing_logic(cursor):
    body_of_loop = None
    # Find the event-loop
    ev_loop = find_event_loop(cursor)
    if ev_loop is None:
        report('Did not found an event loop.')
        # report_on_cursor(cursor)
        body_of_loop = list(cursor.get_children())[-1]
        body_of_loop = skip_unexposed_stmt(body_of_loop)
    else:
        # Go through the AST, generate instructions
        children = list(ev_loop.get_children())
        assert len(children) > 0 and children[-1].kind == clang.CursorKind.COMPOUND_STMT
        body_of_loop = children[-1]

    assert body_of_loop is not None
    return body_of_loop


def get_entry_code(cursor, info):
    tmp_list = find_elem(cursor, info.io_ctx.entry_func)
    if not tmp_list:
        raise Exception('Entry function not found')
    list_entry_functions = list(filter(lambda e: e.kind == clang.CursorKind.FUNCTION_DECL and e.is_definition(), tmp_list))
    assert len(list_entry_functions)  > 0, 'Did not found the entry function'
    assert len(list_entry_functions) == 1, 'Found multiple definition of entry functions'
    entry_func = list_entry_functions[0]
    children = list(entry_func.get_children())
    last_child = children[-1]
    assert last_child.kind == clang.CursorKind.COMPOUND_STMT, 'The entry function does not have an implementation body!'
    body_of_loop = find_request_processing_logic(entry_func)
    return body_of_loop, entry_func
