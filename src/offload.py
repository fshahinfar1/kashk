import clang.cindex as clang
from pprint import pformat

from log import *
from data_structure import *
from instruction import *
from utility import (parse_file, find_elem, add_state_decl_to_bpf,
        report_user_program_graph, draw_tree)
from find_ev_loop import find_request_processing_logic
from sym_table_gen import build_sym_table
from understand_program_state import extract_state, get_state_for
from understand_logic import (get_all_read, get_all_send,
        gather_instructions_from)

from bpf_code_gen import generate_bpf_prog, gen_code
from user import generate_user_prog

from passes.pass_obj import PassObject
from passes.clone import clone_pass
from passes.linear_code import linear_code_pass

from bpf_passes.loop_end import loop_end_pass
from bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from bpf_passes.transform_vars import transform_vars_pass
from bpf_passes.userspace_fallback import userspace_fallback_pass
from bpf_passes.verifier import verifier_pass
from bpf_passes.reduce_params import reduce_params_pass

from user_passes.select_user import select_user_pass
from user_passes.number_fallback_graph import number_fallback_graph_pass
from user_passes.var_dependency import var_dependency_pass
from user_passes.create_fallback import create_fallback_pass


MODULE_TAG = '[Gen Offload]'


def run_pass_on_all_functions(pass_fn, main_inst, info):
    ret = pass_fn(main_inst, info, PassObject())
    for f in Function.directory.values():
        if not f.body.has_children():
            continue
        with info.sym_tbl.with_func_scope(f.name):
            f.body = pass_fn(f.body, info, PassObject())
    return ret


# TODO: make a framework agnostic interface, allow for porting to other
# functions
def generate_offload(io_ctx):
    # TODO: this is the legacy way, update the code to use the context
    file_path = io_ctx.input_file
    entry_func_name = io_ctx.entry_func
    out_bpf = io_ctx.bpf_out_file
    out_user = io_ctx.user_out_file

    # Keep track of which variable name is what, what types has been defined
    # and other information learned about the program
    info = Info()
    info.entry_func_name = entry_func_name
    info.io_ctx = io_ctx

    # This is the AST generated with Clang
    index, tu, cursor = parse_file(file_path, io_ctx.cflags)

    # Collect information about classes, functions, variables, ...
    build_sym_table(cursor, info)

    boot_starp_global_state(cursor, info)

    # Find the entry function
    entry_func = find_elem(cursor, entry_func_name)
    if entry_func is None:
        error('Did not found the entry function')
        return

    # TODO: move the following block of code to some where more appropriate
    # The arguments to the entry function is part of the connection state
    from_entry_params = [get_state_for(arg) for arg in entry_func.get_arguments()]
    for states, decls in from_entry_params:
        add_state_decl_to_bpf(info.prog, states, decls)
        for state in states:
            e = info.sym_tbl.global_scope.insert_entry(state.name, state.type_ref, clang.CursorKind.PARM_DECL, None)
    # debug(MODULE_TAG, from_entry_params)
    # remove the symbols related to the parameters of entry function from its scope (fixing the shadowing effect)
    to_remove = []
    entry_func_name = entry_func_name.replace('::', '_')
    scope = info.sym_tbl.scope_mapping[entry_func_name]
    for k, v in scope.symbols.items():
        if v.kind == clang.CursorKind.PARM_DECL:
            to_remove.append(k)
    for k in to_remove:
        scope.delete(k)

    body_of_loop = find_request_processing_logic(entry_func, info)
    # Find the buffer representing the packet
    find_read_write_bufs(body_of_loop, info)

    # Start the passes
    insts = gather_instructions_from(body_of_loop, info, BODY)
    bpf = Block(BODY)
    bpf.extend_inst(insts)

    ## Simplify Code
    # Move function calls out of the ARG context!
    bpf = run_pass_on_all_functions(linear_code_pass, bpf, info)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # print('Take a peek on the event loop!')
    # text, _ = gen_code(insts, info)
    # print(text)
    # print('------------------------------')
    # text, _ = gen_code(Function.directory['process_request'].body, info)
    # print(text)
    # print('------------------------------')

    ## Feasibility Analysis
    # Mark infeasible paths and annotate which functions may fail or succeed
    bpf = feasibilty_analysis_pass(bpf, info, PassObject())
    # for func in Function.directory.values():
    #     print(func.name, 'may succeed:', func.may_succeed, 'may fail', func.may_fail)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Create the userspace program graph
    select_user_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Number the failure paths
    # number_fallback_graph_pass(info)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Create a clone of unmodified but marked AST, later used for creating the
    # userspace program
    user = clone_pass(bpf, info, PassObject())
    info.user_prog.sym_tbl = info.sym_tbl.clone()
    info.user_prog.func_dir = {}
    for func in Function.directory.values():
        new_f = func.clone(info.user_prog.func_dir)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # TODO: right now the order of generating the userspace and then BPF is important
    gen_user_code(user, info, out_user)
    gen_bpf_code(bpf, info, out_bpf)


def dfs_over_deps_vars(root):
    """
    recursion basis is on the length of children

    @param root: a node of the User Program Graph
    @returns a list of set of variables dependencies a long with the failues number
    """
    this_node_deps = root.paths.var_deps

    if len(root.children) == 0:
        assert len(root.path_ids) == 1, f'Expected the leaf to have one failure number. But it has more/less (list: {root.path_ids})'
        return [{'vars': list(this_node_deps), 'path_id': root.path_ids[0]}]

    results = []
    for child in root.children:
        mid_res = dfs_over_deps_vars(child)
        for r in mid_res:
            r['vars'].extend(this_node_deps)
            results.append(r)
    return results


def gen_user_code(user, info, out_user):
    # Switch the symbol table and functions to the snapshot suitable for
    # userspace analysis
    with info.user_prog.select_context(info):
        create_fallback_pass(user, info, PassObject())
        debug('~~~~~~~~~~~~~~~~~~~~~')
        var_dependency_pass(info)
        debug('~~~~~~~~~~~~~~~~~~~~~')

        # What graph looks like
        # report_user_program_graph(info)

        # Look at var deps
        debug(MODULE_TAG, 'Tree of variable dependencies')
        tree = draw_tree(info.user_prog.graph, fn=lambda x: str(x.paths.var_deps))
        debug(tree)
        # tree = draw_tree(info.user_prog.graph, fn=lambda x: str(id(x)))
        # debug(MODULE_TAG, info.user_prog.graph.paths.var_deps)
        # debug(tree)
        # ----

        meta_structs = dfs_over_deps_vars(info.user_prog.graph)
        debug(MODULE_TAG, 'Metadata structures:', pformat(meta_structs))

        for x in meta_structs:
            state_obj = StateObject(None)
            state_obj.name = 'failure_number'
            state_obj.type_ref = BASE_TYPES[clang.TypeKind.INT]
            state_obj.type = state_obj.type_ref.spelling
            fields = [state_obj,]
            for var in x['vars']:
                # debug(MODULE_TAG, 'bpf/user-shared:', f'{var.name}:{var.type.spelling}')
                # TODO: do I need to clone?
                T = var.type.clone()
                state_obj = StateObject(None)
                state_obj.name = var.name
                state_obj.type = T.spelling
                state_obj.type_ref = T
                fields.append(state_obj)
            path_id = x['path_id']
            meta = Record(f'meta_{path_id}', fields)
            info.prog.add_declaration(meta)
            info.user_prog.declarations.append(meta)

        # Generate the user code in the context of userspace program
        text = generate_user_prog(info)
        debug('~~~~~~~~~~~~~~~~~~~~~')

    with open(out_user, 'w') as f:
        f.write(text)


def gen_bpf_code(bpf, info, out_bpf):
    # End event loop with packet drop
    bpf = loop_end_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Transform access to variables and read/write buffers.
    bpf = run_pass_on_all_functions(transform_vars_pass, bpf, info)
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

    # TODO: what is happening here. Do I need this? I think this is because I
    # was avoiding analysing the parameters of the entry function.
    tcp_conn_entry = info.sym_tbl.lookup('class_TCPConnection')
    if tcp_conn_entry:
        e = info.sym_tbl.global_scope.insert_entry('conn', tcp_conn_entry.type, clang.CursorKind.PARM_DECL, None)
        # Override what the clang thinks
        e.is_pointer = False
        e.name = 'sock_ctx->state.conn'
        # -----------------------------

        # The fields and its dependencies
        ref = find_elem(cursor, 'TCPConnection')
        # states, decls = extract_state(tcp_conn_entry.ref)
        states, decls = extract_state(ref)

        # The input argument is of this type
        tcp_conn_struct = Record('TCPConnection', states)
        decls.append(tcp_conn_struct)

        # The global state has following field
        field = StateObject(tcp_conn_entry.ref)
        field.name = 'conn'
        field.type = 'TCPConnection'
        field.kind = clang.TypeKind.RECORD
        field.type_ref = MyType()
        field.type_ref.spelling = 'struct TCPConnection'
        field.type_ref.kind = field.kind

        add_state_decl_to_bpf(info.prog, [field], decls)


# TODO: the code which finds the buffer is very bad! Re organize and think
# about it!
def find_read_write_bufs(ev_loop, info):
    reads = get_all_read(ev_loop)
    if len(reads) > 1:
        error('Multiple read function was found!')
        return
    for r in reads:
        args = list(r.get_arguments())

        buf_arg = None
        buf_sz = None

        # the buffer is in the first arg
        buf_arg = args[0]
        while buf_arg.kind == clang.CursorKind.UNEXPOSED_EXPR:
            children = list(buf_arg.get_children())
            assert len(children) == 1, f'len(children) == {len(children)}'
            buf_arg = children[0]

        if r.spelling == 'async_read_some':
            buf_arg = args[0]
        elif r.spelling == 'read':
            buf_arg = args[1]
            buf_sz = args[2]

        if buf_arg.kind == clang.CursorKind.CALL_EXPR:
            args = list(buf_arg.get_arguments())
            buf_def = buf_arg.get_definition()
            info.rd_buf = PacketBuffer(buf_def)
            if len(args) == 2:
                buf_sz = args[1]
                info.rd_buf.size_cursor = gather_instructions_from(buf_def, info)
            else:
                # TODO: I need to some how know the size and I might not know
                # it! I can try to find the underlying array. But what if it is
                # not an array?
                error('I need to know the buffer size')
                info.rd_buf.size_cursor = [Literal('2048', clang.CursorKind.INTEGER_LITERAL)]
        else:
            # if the buffer is assigned before and is not a function call
            buf_def = buf_arg.get_definition()
            remove_def = buf_def
            info.remove_cursor.add(remove_def.get_usr())
            report_on_cursor(buf_def)
            if buf_def.kind == clang.CursorKind.CALL_EXPR:
                buf_def = next(buf_def.get_children())
                args = list(buf_def.get_arguments())
                buf_def = args[0].get_definition()
                buf_sz = args[1]
                info.rd_buf = PacketBuffer(buf_def)
                info.rd_buf.size_cursor = gather_instructions_from(buf_sz, info)
            else:
                #TODO: this is awful
                info.rd_buf = PacketBuffer(buf_def)
                if buf_sz is None:
                    children = list(buf_def.get_children())
                    if len(children) > 0:
                        init = children[0]
                        if init.kind == clang.CursorKind.CALL_EXPR:
                            args = list(init.get_arguments())
                            buf_def = args[0].get_definition()
                            buf_sz = args[1]
                            info.rd_buf = PacketBuffer(buf_def)
                            info.rd_buf.size_cursor = gather_instructions_from(buf_sz, info)
                        else:
                            raise Exception('')
                    else:
                        raise Exception('')
                else:
                    info.rd_buf.size_cursor = gather_instructions_from(buf_sz, info)

    if info.rd_buf is None:
        error('Failed to find the packet buffer')
        return

    writes = get_all_send(ev_loop)
    assert len(writes) <= 1, f'I currently expect only one send system call (count found: {len(writes)})'
    for c in writes:
        # TODO: this code is not going to work. it is so specific
        args = list(c.get_arguments())

        buf_arg = None
        buf_sz = None

        if c.spelling == 'async_write':
            buf_arg = args[1]
        elif c.spelling == 'async_write_some':
            buf_arg = args[0]
        elif c.spelling == 'write':
            buf_arg = args[1]
            buf_sz = args[2]

        while buf_arg.kind == clang.CursorKind.UNEXPOSED_EXPR:
            children = list(buf_arg.get_children())
            assert len(children) == 1, f'len(children) == {len(children)}'
            buf_arg = children[0]


        if buf_arg.kind == clang.CursorKind.CALL_EXPR:
            args = list(buf_arg.get_arguments())
            buf_def = args[0].get_definition()
            info.wr_buf = PacketBuffer(buf_def)
            if len(args) == 2:
                buf_sz = args[1]
                info.wr_buf.write_size_cursor = gather_instructions_from(buf_sz, info)
            else:
                # TODO: I need to some how know the size and I might not know
                # it! I can try to find the underlying array. But what if it is
                # not an array?
                error('I need to know the buffer size')
                info.wr_buf.write_size_cursor = [Literal('2048', clang.CursorKind.INTEGER_LITERAL)]
        else:
            buf_def = buf_arg.get_definition()
            remove_def = buf_def
            # info.remove_cursor.add(remove_def.get_usr())
            if buf_def.kind == clang.CursorKind.CALL_EXPR:
                buf_def = next(buf_def.get_children())
                args = list(buf_def.get_arguments())
                buf_def = args[0].get_definition()
                buf_sz = args[1]
                info.wr_buf = PacketBuffer(buf_def)
                info.wr_buf.write_size_cursor = gather_instructions_from(buf_sz, info)
            else:
                info.wr_buf = PacketBuffer(buf_def)
                if buf_sz is None:
                    children = list(buf_def.get_children())
                    if len(children) > 0:
                        init = children[0]
                        if init.kind == clang.CursorKind.CALL_EXPR:
                            args = list(init.get_arguments())
                            buf_def = args[0].get_definition()
                            buf_sz = args[1]
                            info.wr_buf = PacketBuffer(buf_def)
                            info.wr_buf.write_size_cursor = gather_instructions_from(buf_sz, info)
                        else:
                            raise Exception('')
                    else:
                        raise Exception('')
                else:
                    info.wr_buf.write_size_cursor = gather_instructions_from(buf_sz, info)
