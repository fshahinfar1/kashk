import clang.cindex as clang
from pprint import pformat

from log import *
from data_structure import *
from instruction import *
from utility import (parse_file, find_elem, add_state_decl_to_bpf,
        report_user_program_graph, draw_tree, show_insts)
from find_ev_loop import get_entry_code
from sym_table_gen import build_sym_table, process_source_file
from understand_program_state import extract_state, get_state_for
from understand_logic import (get_all_read, get_all_send,
        gather_instructions_from)
from understand_logic_handler import create_func_objs

from mark_io import mark_io

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
from bpf_passes.mark_used_funcs import mark_used_funcs

from user_passes.select_user import select_user_pass
from user_passes.number_fallback_graph import number_fallback_graph_pass
from user_passes.var_dependency import var_dependency_pass
from user_passes.create_fallback import create_fallback_pass


MODULE_TAG = '[Gen Offload]'


def run_pass_on_all_functions(pass_fn, main_inst, info, skip_if=lambda x: False):
    ret = pass_fn(main_inst, info, PassObject())
    for f in Function.directory.values():
        if f.is_empty() or skip_if(f):
            continue
        with info.sym_tbl.with_func_scope(f.name):
            f.body = pass_fn(f.body, info, PassObject())
    return ret


def _print_code(prog, info):
    text, _ =  gen_code(prog, info)
    debug('code:\n', text, '\n---', sep='')


def load_other_sources(io_ctx, info):
    # This is the AST generated with Clang
    others = []
    for path in io_ctx.other_source_files:
        report('Load:', path)
        _, _, other_cursor = parse_file(path, io_ctx.cflags)
        others.append(other_cursor)
        process_source_file(other_cursor, info)

# TODO: make a framework agnostic interface, allow for porting to other
# functions
def generate_offload(io_ctx):
    info = Info.from_io_ctx(io_ctx)
    # Parse the main file
    index, tu, cursor = parse_file(info.io_ctx.input_file, io_ctx.cflags)
    # Parse other files. Collect information about classes, functions, variables, ...
    build_sym_table(cursor, info)
    # Load other source files
    load_other_sources(io_ctx, info)
    # Select the main scope
    scope = info.sym_tbl.scope_mapping[info.io_ctx.entry_func]
    info.sym_tbl.current_scope = scope
    # Find the entry function
    main = get_entry_code(cursor, info)

    # Start the passes
    debug('First pass on the AST (initializing...)')
    insts = gather_instructions_from(main, info, BODY)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    debug('Gather Infromation About Functions')
    create_func_objs(info)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # We have our own AST now, continue processing ...
    bpf = Block(BODY)
    bpf.extend_inst(insts)

    debug('Mark Read/Write Inst & Buf')
    mark_io(bpf, info)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    ## Simplify Code
    # Move function calls out of the ARG context!
    debug('Linear Code')
    bpf = linear_code_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    ## Feasibility Analysis
    debug('Feasibility Analysis')
    bpf = feasibilty_analysis_pass(bpf, info, PassObject())
    # for func in sorted(Function.directory.values(), key=lambda x: x.name):
    #     debug(func.name, 'may succeed:', func.may_succeed, 'may fail', func.may_fail, func.path_ids)
    # code, _ = gen_code(bpf, info)
    # print(code)
    # show_insts([bpf])

    # func = Function.directory.get('memmove')
    # assert func is not None
    # print(func.name, func.may_succeed, func.may_fail)

    # func = Function.directory.get('try_read_udp')
    # assert func
    # show_insts(func.body)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Create the userspace program graph
    select_user_pass(bpf, info, PassObject())
    tree = draw_tree(info.user_prog.graph, fn=lambda x: str(id(x)))
    # tree = draw_tree(info.user_prog.graph, fn=lambda x: str(id(x)) + str(x.path_ids))
    debug(tree)
    # root = info.user_prog.graph
    # code = root.paths.code
    # debug(id(root), root.children, code)
    # text, _ =  gen_code(code, info)
    # debug('code:\n', text, '\n---', sep='')
    # debug('is user empty:', root.is_empty())
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
    if not info.user_prog.graph.is_empty():
        gen_user_code(user, info, io_ctx.user_out_file)
    else:
        report("No user space program was generated. The tool has offloaded everything to BPF.")
    gen_bpf_code(bpf, info, io_ctx.bpf_out_file)


def dfs_over_deps_vars(root):
    """
    recursion basis is on the length of children

    @param root: a node of the User Program Graph
    @returns a list of set of variables dependencies along with the failure number
    """
    this_node_deps = root.paths.var_deps

    if len(root.children) == 0:
        if len(root.path_ids) != 1:
            return [{'vars': [], 'path_id': '-'}]
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
    debug('Loop End')
    bpf = loop_end_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Transform access to variables and read/write buffers.
    debug('Transform Vars')
    bpf = run_pass_on_all_functions(transform_vars_pass, bpf, info)
    # code, _ = gen_code(bpf, info)
    # print(code)
    # show_insts([bpf])
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Handle moving to userspace and removing the instruction not possible in
    # BPF
    debug('Userspace Fallback')
    bpf = userspace_fallback_pass(bpf, info, PassObject())
    # code, _ = gen_code(bpf, info)
    # print(code)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Verifier
    debug('Verifier')
    bpf = verifier_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Reduce number of parameters
    debug('Reduce Params')
    bpf = reduce_params_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Mark which type or func definitions should be placed in generated code
    debug('Mark Functions used in BPF')
    mark_used_funcs(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # TODO: split the code between parser and verdict
    debug('[Parser/Verdict Split Code]')
    info.prog.set_code(bpf)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Write the code we have generated
    debug('BPF Code Generation')
    text = generate_bpf_prog(info)
    with open(out_bpf, 'w') as f:
        f.write(text)
    debug('~~~~~~~~~~~~~~~~~~~~~')
