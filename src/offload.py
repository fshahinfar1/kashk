import sys
import clang.cindex as clang
import queue

from utility import parse_file, find_elem, get_code
from understand_program_state import extract_state, get_state_for
from understand_logic import (find_event_loop,
        get_variable_declaration_before_elem, get_all_read,
        gather_instructions_under, VarDecl)
from bpf import SK_SKB_PROG


def generate_offload(file_path, entry_func):
    # This is the BPF program object we want to build
    prog = SK_SKB_PROG()
    # This is the AST generated with Clang
    index, tu, cursor = parse_file(file_path)
    # Find the entry function
    entry_func = find_elem(cursor, 'Server::handle_connection')
    if entry_func is None:
        print('Did not found the entry function', file=sys.stderr)
        return

    # The arguments to the entry function is part of the connection state
    # entry_func_params = [get_state_for(arg) for arg in entry_func.get_arguments()]
    tcp_conn = find_elem(cursor, 'TCPConnection')
    states, decls = extract_state(tcp_conn)
    add_state_decl_to_bpf(prog, states, decls)

    # Find the event-loop
    ev_loop = find_event_loop(entry_func)
    # All declerations between event loop is shared among multiple packets of
    # one connection
    all_declerations_before_loop = get_variable_declaration_before_elem(entry_func, ev_loop)
    for d in all_declerations_before_loop:
        states, decls = get_state_for(d.cursor)
        add_state_decl_to_bpf(prog, states, decls)

    # TODO: all the initialization and operations done before the event loop is
    # probably part of the control program setting up the BPF program.

    # TODO: make a framework agnostic interface, allow for porting to other
    # functions
    # Find the buffer representing the packet
    buf = None
    reads = get_all_read(ev_loop)
    for r in reads:
        # the buffer is in the first arg
        first_arg = list(r.get_arguments())[0]
        buf = first_arg.get_definition()
        print('\nThe buffer for reading request:')
        print(get_code(buf))
        print('')
        # TODO: if there are reads from different sockets, bail out!
    if buf is None:
        print('Failed to find the packet buffer', file=sys.stderr)
        return

    # Go through the instructions, replace access to the buffer and read/write
    # instructions
    body_of_loop = list(ev_loop.get_children())[-1]
    inst = gather_instructions_under(body_of_loop, buf, None)

    # Show what are the instructions
    print('\n\n')
    __show_insts(inst)

    # # Get logic code
    # prog.parser_prog = logic_code

    # Print the code we have generated
    # print(prog.get_code())


def __show_insts(lst, depth=0):
    for i in lst:
        print('  '*depth + str(i))
        if i.has_children():
            __show_insts(i.body, depth=depth+1)
            print('  '*depth + '<OTHERWISE>')
            __show_insts(i.other_body, depth=depth+1)
            print('  '*depth + '<END>')



def add_state_decl_to_bpf(prog, states, decls):
    for s in states:
        prog.add_connection_state(s)
    for d in decls:
        prog.add_declaration(d)
