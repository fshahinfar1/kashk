import sys
import clang.cindex as clang
import queue

from utility import parse_file, find_elem, get_code
from understand_program_state import extract_state
from understand_logic import go_through_the_code
from bpf import SK_SKB_PROG


def generate_offload(file_path, entry_func):
    # This is the BPF program object we want to build
    prog = SK_SKB_PROG()
    # This is the AST generated with Clang
    cursor = parse_file(file_path)

    # for c in cursor.get_children():
    #     if 'Server' in c.spelling:
    #         for c2 in c.get_children():
    #             print(c2.spelling, c2.kind)

    # Get the state needed for handling the request
    states, decls = extract_state(cursor)
    for s in states:
        prog.add_connection_state(s)
    for d in decls:
        prog.add_decleration(d)

    # Get logic code
    process_entry_function(cursor)

    # Print the code we have generated
    # print(prog.get_code())


def process_entry_function(cursor):
    # Expect the entry function at Server::handle_connection(TCPConnection)
    func = find_elem(cursor, 'Server::handle_connection')
    if func is None:
        print('Did not found the entry function', file=sys.stderr)
        return

    go_through_the_code(func)

    # text = get_code(func)
    # print(text)

