import clang.cindex as clang

from utility import parse_file, find_elem
from understand_program_state import (extract_state, get_state_for,)
from understand_logic import (find_event_loop,
        get_variable_declaration_before_elem, get_all_read, get_all_send,
        gather_instructions_under, gather_instructions_from)

from data_structure import *
from instruction import *

from bpf_code_gen import generate_bpf_prog, gen_code
from user import generate_user_prog
from sym_table import SymbolTableEntry
from sym_table_gen import build_sym_table

from passes.pass_obj import PassObject
from passes.clone import clone_pass
from passes.linear_code import linear_code_pass
# from passes.cfg_gen import cfg_gen_pass

from bpf_passes.loop_end import loop_end_pass
from bpf_passes.possible_path_analysis import possible_path_analysis_pass
from bpf_passes.transform_vars import transform_vars_pass
from bpf_passes.userspace_fallback import userspace_fallback_pass
from bpf_passes.verifier import verifier_pass
from bpf_passes.reduce_params import reduce_params_pass

from user_passes.select_user import select_user_pass
from user_passes.number_fallback_graph import number_fallback_graph_pass
from user_passes.var_dependency import var_dependency_pass
from user_passes.create_fallback import create_fallback_pass


# TODO: make a framework agnostic interface, allow for porting to other
# functions
def generate_offload(file_path, entry_func_name, out_bpf, out_user):
    # Keep track of which variable name is what, what types has been defined
    # and other information learned about the program
    info = Info()
    info.entry_func_name = entry_func_name

    # This is the AST generated with Clang
    index, tu, cursor = parse_file(file_path)

    # Collect information about classes, functions, variables, ...
    build_sym_table(cursor, info)

    # Find the entry function
    entry_func = find_elem(cursor, entry_func_name)
    if entry_func is None:
        error('Did not found the entry function')
        return

    # The arguments to the entry function is part of the connection state
    # entry_func_params = [get_state_for(arg) for arg in entry_func.get_arguments()]
    boot_starp_global_state(cursor, info)

    # Find the event-loop
    ev_loop = find_event_loop(entry_func)
    if ev_loop is None:
        error('Did not found event loop')
        debug('Assuming it is a test case!')
        body_of_loop = list(entry_func.get_children())[-1]
        insts = gather_instructions_under(body_of_loop, info, BODY)
    else:
        # All declarations between event loop is shared among multiple packets of
        # one connection
        all_declarations_before_loop = get_variable_declaration_before_elem(entry_func, ev_loop, info)
        for d in all_declarations_before_loop:
            states, decls = get_state_for(d.cursor)
            add_state_decl_to_bpf(info.prog, states, decls)
            for s in states:
                s.is_global = True
                # Add it to the global scope
                c = s.cursor
                entry = SymbolTableEntry(c.spelling, c.type, c.kind, c)
                info.sym_tbl.global_scope.insert(entry)

        # TODO: all the initialization and operations done before the event loop is
        # probably part of the control program setting up the BPF program.

        # Find the buffer representing the packet
        find_read_write_bufs(ev_loop, info)

        # Go through the AST, generate instructions
        body_of_loop = list(ev_loop.get_children())[-1]
        insts = gather_instructions_under(body_of_loop, info, BODY)


    # TODO: Think more about the API of each pass
    bpf = Block(BODY)
    bpf.extend_inst(insts)

    ## Simplify Code
    # Move function calls out of the ARG context!
    bpf = linear_code_pass(bpf, info, PassObject())
    for f in Function.directory.values():
        with info.sym_tbl.with_func_scope(f.name):
            f.body = linear_code_pass(f.body, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    ## Possible Path Analysis
    # Mark inpossible paths and annotate which functions may fail or suceed
    bpf = possible_path_analysis_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Create a clone of unmodified but marked AST, later used for creating the
    # userspace program
    user = clone_pass(bpf, info, PassObject())
    info.user_prog.sym_tbl = info.sym_tbl.clone()
    info.user_prog.func_dir = {}
    for func in Function.directory.values():
        new_f = func.clone(info.user_prog.func_dir)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    gen_user_code(user, info, out_user)
    gen_bpf_code(bpf, info, out_bpf)


def gen_user_code(user, info, out_user):
    # Switch the symbol table and functions to the snapshot suitable for
    # userspace analysis
    with info.user_prog.select_context(info):
        # Populates the user_prog graph
        select_user_pass(user, info, PassObject())
        number_fallback_graph_pass(info)

        create_fallback_pass(user, info, PassObject()) 
        var_dependency_pass(info)

        # # What graph looks like
        # q = [info.user_prog.graph, 0]
        # lvl = 0
        # while q:
        #     node = q.pop()
        #     if node == 0:
        #         lvl += 1
        #         continue
        #     debug('lvl:', lvl, 'children:', len(node.children), node.paths.code.children)
        #     q.extend(reversed(node.children))
        #     q.append(0)

        # Look at the status
        # q = [info.user_prog.graph, 0]
        # lvl = 0
        # while q:
        #     node = q.pop()
        #     if node == 0:
        #         lvl += 1
        #         continue
        #     debug('lvl:', lvl)
        #     debug(node.paths.var_deps)
        #     q.extend(reversed(node.children))
        #     q.append(0)

        # debug(info.user_prog.graph.paths.var_deps)
        fields = []
        for var in info.user_prog.graph.paths.var_deps:
            T = MyType()
            T.kind = var.type.kind
            T.spelling = var.type.spelling
            state_obj = StateObject(None)
            state_obj.name = var.name
            state_obj.type = T.spelling
            state_obj.type_ref = T
            fields.append(state_obj)
        meta = Record('meta', fields)
        info.prog.add_declaration(meta)
        info.user_prog.declarations.append(meta)

        # Generate the user code in the context of userspace program
        text = generate_user_prog(info)

    with open(out_user, 'w') as f:
        f.write(text)


def gen_bpf_code(bpf, info, out_bpf):
    # End event loop with packet drop
    bpf = loop_end_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Transform access to variables and read/write buffers.
    bpf = transform_vars_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Handle moving to userspace and removing the instruction not possible in
    # BPF
    bpf = userspace_fallback_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Verifier
    bpf = verifier_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Reduce number of parameters
    bpf = reduce_params_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # TODO: split the code between parser and verdict
    bpf_parser = Block(BODY)
    bpf_parser.add_inst(Literal('return skb->len;', CODE_LITERAL))
    info.prog.parser_code = bpf_parser
    info.prog.verdict_code = bpf

    # Write the code we have generated
    text = generate_bpf_prog(info)
    with open(out_bpf, 'w') as f:
        f.write(text)


def boot_starp_global_state(cursor, info):
    """
    This function prepares the initial scope for processing phase. In the
    processing phase we go throught the instructions and understand the program
    logic. The understanding is used for further transformation to BPF program.
    """
    # Set the scope to the Server::handle_connection
    entry_name = info.entry_func_name
    entry_name = entry_name.replace('::', '_')
    scope = info.sym_tbl.scope_mapping[entry_name]
    info.sym_tbl.current_scope = scope

    tcp_conn_entry = info.sym_tbl.lookup('class_TCPConnection')
    if tcp_conn_entry:
        e = info.sym_tbl.insert_entry('conn', tcp_conn_entry.type, clang.CursorKind.PARM_DECL, None)
        # Override what the clang thinks
        e.is_pointer = False
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
        field.type_ref = MyType()
        field.type_ref.spelling = 'struct TCPConnection'
        field.type_ref.kind = field.kind

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
        args = list(c.get_arguments())
        buf_def = args[1].get_definition()
        remove_def = buf_def
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
