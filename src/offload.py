import sys
import clang.cindex as clang
import queue

from utility import parse_file, find_elem, show_insts, report_on_cursor
from understand_program_state import (extract_state, get_state_for,)
from understand_logic import (find_event_loop,
        get_variable_declaration_before_elem, get_all_read, get_all_send,
        gather_instructions_under, gather_instructions_from)
from data_structure import *
from instruction import *
from bpf_code_gen import generate_bpf_prog

from sym_table import scope_mapping, SymbolTableEntry
from sym_table_gen import build_sym_table
from verifier import verifier_pass
from possible_path_analysis import possible_path_analysis_pass


# TODO: make a framework agnostic interface, allow for porting to other
# functions
def generate_offload(file_path, entry_func):
    # Keep track of which variable name is what, what types has been defined
    # and other information learned about the program
    info = Info()

    # This is the AST generated with Clang
    index, tu, cursor = parse_file(file_path)

    # Collect information about classes, functions, variables, ...
    build_sym_table(cursor, info)

    # Find the entry function
    entry_func = find_elem(cursor, 'Server::handle_connection')
    if entry_func is None:
        error('Did not found the entry function')
        return

    # The arguments to the entry function is part of the connection state
    # entry_func_params = [get_state_for(arg) for arg in entry_func.get_arguments()]
    boot_starp_global_state(cursor, info)

    # Find the event-loop
    ev_loop = find_event_loop(entry_func)

    # All declerations between event loop is shared among multiple packets of
    # one connection
    all_declerations_before_loop = get_variable_declaration_before_elem(entry_func, ev_loop, info)
    for d in all_declerations_before_loop:
        states, decls = get_state_for(d.cursor)
        add_state_decl_to_bpf(info.prog, states, decls)
        for s in states:
            s.is_global = True
            s.parent_object = None
            # Add it to the global scope
            c = s.cursor
            entry = SymbolTableEntry(c.spelling, c.type, c.kind, c)
            info.sym_tbl.global_scope.insert(entry)

    # TODO: all the initialization and operations done before the event loop is
    # probably part of the control program setting up the BPF program.

    # Find the buffer representing the packet
    find_read_write_bufs(ev_loop, info)

    # Go through the AST, generate instructions, transform access to variables
    # and read/write buffers.
    body_of_loop = list(ev_loop.get_children())[-1]
    insts = gather_instructions_under(body_of_loop, info, BODY)

    inst = Block(BODY)
    inst.children = insts
    # Cut inpossible paths
    m = possible_path_analysis_pass(inst, info, (0, BODY, None))

    debug('~~~~~~~~~~~~~~~~~~~~~')
    for func in Function.directory.values():
        debug(func.name, 'may_fail:', func.may_fail, 'may_succeed:',
                func.may_succeed)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Verifier
    m = verifier_pass(m, info, (0, inst.tag, None))

    info.prog.parser_code = m

    # Print the code we have generated
    text = generate_bpf_prog(info)
    print(text)


def boot_starp_global_state(cursor, info):
    """
    This function prepares the initial scope for processing phase. In the
    processing phase we go throught the instructions and understand the program
    logic. The understanding is used for further transformation to BPF program.
    """
    # Set the scope to the Server::handle_connection
    scope = scope_mapping['Server_handle_connection']
    info.sym_tbl.current_scope = scope

    tcp_conn_entry = info.sym_tbl.lookup('class_TCPConnection')
    e = info.sym_tbl.insert_entry('conn', tcp_conn_entry.type, clang.CursorKind.PARM_DECL, None)
    # Override what the clang thinks
    e.is_pointer = True
    e.name = 'sock_ctx->state.conn'
    # -----------------------------

    # The fields and its dependencies
    states, decls = extract_state(tcp_conn_entry.ref)

    # The input argument is of this type
    tcp_conn_struct = Record('TCPConnection', states)
    decls.append(tcp_conn_struct)

    # The global state has following field
    field = StateObject(tcp_conn_entry.ref)
    field.name = 'conn'
    field.type = 'TCPConnection'
    field.kind = clang.TypeKind.RECORD
    field.is_global = True
    field.type_ref = tcp_conn_struct
    field.parent_object = None

    for s in states:
        s.parent_object = field

    add_state_decl_to_bpf(info.prog, [field], decls)


def find_read_write_bufs(ev_loop, info):
    reads = get_all_read(ev_loop)
    if len(reads) > 1:
        error('Multiple read function was found!')
        return
    for r in reads:
        # the buffer is in the first arg
        first_arg = list(r.get_arguments())[0]
        # TODO: Only if the buffer is assigned before and is not a function call
        buf_def = first_arg.get_definition()
        remove_def = buf_def
        buf_def = next(buf_def.get_children())
        args = list(buf_def.get_arguments())
        buf_def = args[0].get_definition()
        buf_sz = args[1]
        info.rd_buf = PacketBuffer(buf_def)
        info.rd_buf.size_cursor = gather_instructions_from(buf_def, info)
        info.remove_cursor.add(remove_def.get_usr())
    if info.rd_buf is None:
        error('Failed to find the packet buffer')
        return

    writes = get_all_send(ev_loop)
    assert len(writes) == 1, 'I currently expect only one send system call'
    for c in writes:
        # TODO: this code is not going to work. it is so specific
        # report_on_cursor(c)
        args = list(c.get_arguments())
        buf_def = args[1].get_definition()
        remove_def = buf_def
        # report_on_cursor(buf_def)
        buf_def = next(buf_def.get_children())
        args = list(buf_def.get_arguments())
        buf_def = args[0].get_definition()
        buf_sz = args[1]
        info.wr_buf = PacketBuffer(buf_def)
        info.wr_buf.write_size_cursor = gather_instructions_from(buf_sz, info)
        info.remove_cursor.add(remove_def.get_usr())


def add_state_decl_to_bpf(prog, states, decls):
    for s in states:
        prog.add_connection_state(s)
    for d in decls:
        prog.add_declaration(d)
