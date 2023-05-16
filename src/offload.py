import sys
import clang.cindex as clang
import queue

from utility import parse_file, find_elem, get_code, show_insts
from understand_program_state import (extract_state, get_state_for,)
from understand_logic import (find_event_loop,
        get_variable_declaration_before_elem, get_all_read,
        gather_instructions_under)
from bpf import SK_SKB_PROG
from bpf_code_gen import gen_program
from data_structure import *


def generate_offload(file_path, entry_func):
    # Keep track of which variable name is what, what types has been defined
    # and other information learned about the program
    info = Info()
    # This is the AST generated with Clang
    index, tu, cursor = parse_file(file_path)
    # Find the entry function
    entry_func = find_elem(cursor, 'Server::handle_connection')
    if entry_func is None:
        print('Did not found the entry function', file=sys.stderr)
        return
    # The arguments to the entry function is part of the connection state
    # entry_func_params = [get_state_for(arg) for arg in entry_func.get_arguments()]
    boot_starp_global_state(cursor, info)
    # Find the event-loop
    ev_loop = find_event_loop(entry_func)
    # All declerations between event loop is shared among multiple packets of
    # one connection
    all_declerations_before_loop = get_variable_declaration_before_elem(entry_func, ev_loop)
    for d in all_declerations_before_loop:
        states, decls = get_state_for(d.cursor)
        add_state_decl_to_bpf(info.prog, states, decls)
        for s in states:
            s.is_global = True
            info.scope.add_global(s.name, s)

    # TODO: all the initialization and operations done before the event loop is
    # probably part of the control program setting up the BPF program.

    # TODO: make a framework agnostic interface, allow for porting to other
    # functions
    # Find the buffer representing the packet
    reads = get_all_read(ev_loop)
    for r in reads:
        # the buffer is in the first arg
        first_arg = list(r.get_arguments())[0]
        info.rd_buf = PacketBuffer(first_arg.get_definition())
        # TODO: if there are reads from different sockets, bail out!
    if info.rd_buf is None:
        print('Failed to find the packet buffer', file=sys.stderr)
        return


    print('The state until now is:')
    print(info.scope.glbl)
    print(info.scope.local)
    print('-------------------------------------\n')

    # Go through the instructions, replace access to the buffer and read/write
    # instructions
    body_of_loop = list(ev_loop.get_children())[-1]
    insts = gather_instructions_under(body_of_loop, info)

    # Going through the instructions and generating BPF code
    print('\n\n')
    text = gen_program(insts, info)
    print(text)

    # Show what are the instructions (DEBUGING
    print('\n\n')
    show_insts(insts)

    # # Get logic code
    # prog.parser_prog = logic_code

    # Print the code we have generated
    # print(prog.get_code())


def boot_starp_global_state(cursor, info):
    # Per connection state class
    tcp_conn = find_elem(cursor, 'TCPConnection')
    # The fields and its dependencies
    states, decls = extract_state(tcp_conn)

    # The input argument is of this type
    tcp_conn_struct = Record('TCPConnection', states)
    decls.append(tcp_conn_struct)

    # The global state has following field
    field = StateObject(tcp_conn)
    field.cursor = None
    field.name = 'conn'
    field.type = 'TCPConnection'
    field.kind = clang.TypeKind.RECORD
    field.is_global = True
    field.type_ref = tcp_conn_struct

    add_state_decl_to_bpf(info.prog, [field], decls)
    info.scope.add_global(field.name, field)

def add_state_decl_to_bpf(prog, states, decls):
    for s in states:
        prog.add_connection_state(s)
    for d in decls:
        prog.add_declaration(d)
