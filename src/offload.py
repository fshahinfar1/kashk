import sys
import clang.cindex as clang
import queue

from utility import parse_file, find_elem, get_code
from understand_program_state import extract_state, get_state_for
from understand_logic import find_event_loop, get_variable_declaration_before_elem
from bpf import SK_SKB_PROG


def generate_offload(file_path, entry_func):
    # This is the BPF program object we want to build
    prog = SK_SKB_PROG()
    # This is the AST generated with Clang
    cursor = parse_file(file_path)
    # Find the entry function
    entry_func = find_elem(cursor, 'Server::handle_connection')
    if entry_func is None:
        print('Did not found the entry function', file=sys.stderr)
        return

    # The arguments to the entry function is part of the connection state
    # entry_func_params = [get_state_for(arg) for arg in entry_func.get_arguments()]
    tcp_conn = find_elem(cursor, 'TCPConnection')
    states, decls = extract_state(tcp_conn)
    for s in states:
        prog.add_connection_state(s)
    for d in decls:
        prog.add_declaration(d)

    # Find the event-loop
    ev_loop = find_event_loop(entry_func)
    # All declerations between event loop is shared among multiple packets of
    # one connection
    all_declerations_before_loop = get_variable_declaration_before_elem(entry_func, ev_loop)
    for d in all_declerations_before_loop:
        states, decl = get_state_for(d.cursor)
        for s in states:
            prog.add_connection_state(s)
        for d in decls:
            prog.add_declaration(d)

    # # Get logic code
    # prog.parser_prog = logic_code

    # Print the code we have generated
    print(prog.get_code())

