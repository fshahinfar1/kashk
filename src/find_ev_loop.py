import clang.cindex as clang

from log import error, debug, report
from utility import skip_unexposed_stmt, add_state_decl_to_bpf, get_body_of_the_loop, report_on_cursor
from sym_table import SymbolTableEntry
from understand_logic import (get_variable_declaration_before_elem,
        find_event_loop, get_state_for)


def find_request_processing_logic(cursor, info):
    body_of_loop = None
    # Find the event-loop
    ev_loop = find_event_loop(cursor)
    if ev_loop is None:
        report('Did not found an event loop.')
        # report_on_cursor(cursor)
        body_of_loop = list(cursor.get_children())[-1]
        body_of_loop = skip_unexposed_stmt(body_of_loop)
    else:
        # All declarations between event loop is shared among multiple packets
        # of one connection
        all_declarations_before_loop = get_variable_declaration_before_elem(cursor, ev_loop, info)
        for d in all_declarations_before_loop:
            states, decls = get_state_for(d.cursor)
            add_state_decl_to_bpf(info.prog, states, decls)
            for s in states:
                # Add it to the global scope
                c = s.cursor
                entry = SymbolTableEntry(c.spelling, c.type, c.kind, c)
                info.sym_tbl.global_scope.insert(entry)

        # TODO: all the initialization and operations done before the event loop is
        # probably part of the control program setting up the BPF program.

        # Go through the AST, generate instructions
        body_of_loop = get_body_of_the_loop(ev_loop)

    assert body_of_loop is not None
    return body_of_loop
