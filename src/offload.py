import clang.cindex as clang
from pprint import pformat

from framework_support import InputOutputContext
from log import *
from data_structure import *
from instruction import *
from utility import (parse_file, find_elem, report_user_program_graph,
        draw_tree)
from find_ev_loop import get_entry_code
from sym_table import Scope
from sym_table_gen import build_sym_table, process_source_file
from understand_logic import  (gather_instructions_from,
        get_variable_declaration_before_elem)
from understand_logic_handler import create_func_objs, add_known_func_objs

from bpf_code_gen import generate_bpf_prog, gen_code
from user import generate_user_prog

from passes.pass_obj import PassObject
from passes.mark_used_funcs import mark_used_funcs
from passes.replace_func_ptr import replace_func_pointers
from passes.mark_io import mark_io
from passes.clone import clone_pass
from passes.linear_code import linear_code_pass

from bpf_passes.loop_end import loop_end_pass
from bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from bpf_passes.transform_vars import transform_vars_pass
from bpf_passes.userspace_fallback import userspace_fallback_pass
from bpf_passes.verifier import verifier_pass
from bpf_passes.transform_after_verifier import transform_func_after_verifier
from bpf_passes.reduce_params import reduce_params_pass
from bpf_passes.remove_everything_not_used import remove_everything_not_used

from user_passes.select_user import select_user_pass
from user_passes.number_fallback_graph import number_fallback_graph_pass
from user_passes.var_dependency import var_dependency_pass
from user_passes.create_fallback import create_fallback_pass

from helpers.instruction_helper import show_insts


MODULE_TAG = '[Gen Offload]'
BPF_MAIN = 'BPF_MAIN_SCOPE'


def _print_code(prog, info):
    text, _ =  gen_code(prog, info)
    debug('code:\n', text, '\n---', sep='')


def _prepare_event_handler_args(cursor, info):
    if info.io_ctx.bpf_hook == InputOutputContext.HOOK_XDP:
        # Find a special function in the main file
        list_elem = find_elem(cursor, '_prepare_event_handler_args')
        if list_elem is None:
            return []
        assert len(list_elem) == 1, 'Need to find one and only one implementation of this function'
        func = list_elem[0]
        assert func.kind == clang.CursorKind.FUNCTION_DECL
        assert func.is_definition()
        body = list(func.get_children())[-1]
        assert body.kind == clang.CursorKind.COMPOUND_STMT
        insts = gather_instructions_from(body, info, BODY)
        return insts
    elif info.io_ctx.bpf_hook == InputOutputContext.HOOK_SK_SKB:
        # Add the entry function to the per connection map ?
        entry_func = Function.directory[info.io_ctx.entry_func]
        for arg in entry_func.get_arguments():
            # TODO: global scope is shared_scope
            # the global_scope is the per connection scope
            # This is crazy. Why did I not fix this before. I should correct it

            # NOTE: the arguments of the event handler function are put on a
            # map for future access (connection context)
            assert not arg.type_ref.is_pointer(), 'Putting a pointer on the shared map is incorrect'
            info.sym_tbl.shared_scope.insert_entry(arg.name,
                    arg.type_ref, clang.CursorKind.PARM_DECL, None)
    # No instructions to be added
    return []


def load_other_sources(io_ctx, info):
    # This is the AST generated with Clang
    others = []
    for path in io_ctx.other_source_files:
        report('Load:', path)
        _, _, other_cursor = parse_file(path, io_ctx.cflags)
        others.append(other_cursor)
        process_source_file(other_cursor, info)

def generate_offload(io_ctx):
    info = Info.from_io_ctx(io_ctx)
    # Parse the main file
    index, tu, cursor = parse_file(info.io_ctx.input_file, io_ctx.cflags)
    # Parse other files. Collect information about classes, functions,
    # variables, ...
    build_sym_table(cursor, info)
    # Load other source files
    load_other_sources(io_ctx, info)
    # Select the main scope
    scope = Scope(info.sym_tbl.global_scope)
    info.sym_tbl.scope_mapping[BPF_MAIN] = scope
    info.sym_tbl.current_scope = scope
    info.prog.add_args_to_scope(scope)
    # Find the entry function
    main, entry_func = get_entry_code(cursor, info)


    list_vars = get_variable_declaration_before_elem(entry_func, main)
    if list_vars:
        debug('This is the list of variables before event loop:')
        debug(tuple(map(lambda x: f'{x.name}:{x.type.spelling}', list_vars)))
        debug('-------------------------------------------------')

    # Start the passes
    debug('First pass on the AST (initializing...)')
    insts = gather_instructions_from(main, info, BODY)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    debug('Gather Infromation About Functions')
    create_func_objs(info)
    add_known_func_objs(info)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Prepare the event handler arguments
    prepare_insts = _prepare_event_handler_args(cursor, info)

    # We have our own AST now, continue processing ...
    bpf = Block(BODY)
    bpf.extend_inst(prepare_insts)
    bpf.extend_inst(insts)

    # Mark which type or func definitions should be placed in generated code
    debug('Mark Functions used in BPF')
    mark_used_funcs(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    debug('Replace Function Pointers')
    bpf = replace_func_pointers(bpf, info, None)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    debug('Mark Read/Write Inst & Buf')
    mark_io(bpf, info)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    debug('Linear Code')
    bpf = linear_code_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    debug('Feasibility Analysis')
    bpf = feasibilty_analysis_pass(bpf, info, PassObject())
    # for func in sorted(Function.directory.values(), key=lambda x: x.name):
    #     debug(func.name, 'may succeed:', func.may_succeed, 'may fail', func.may_fail, func.path_ids)
    # code, _ = gen_code(bpf, info)
    # print(code)
    # show_insts([bpf])

    # func = Function.directory.get('strlen')
    # assert func is not None
    # debug(func.name, func.may_succeed, func.may_fail)

    # func = Function.directory.get('tokenize_command')
    # assert func is not None
    # debug(func.name, func.may_succeed, func.may_fail)
    # assert 0

    # func = Function.directory.get('try_read_udp')
    # assert func
    # show_insts(func.body)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    debug('Create User Code Graph')
    select_user_pass(bpf, info, PassObject())
    # tree = draw_tree(info.user_prog.graph, fn=lambda x: str(id(x)))
    # tree = draw_tree(info.user_prog.graph, fn=lambda x: str(id(x)) + str(x.path_ids))
    # debug(tree)
    # root = info.user_prog.graph
    # code = root.paths.code
    # debug(id(root), root.children, code)
    # text, _ =  gen_code(code, info)
    # debug('code:\n', text, '\n---', sep='')
    # debug('is user empty:', root.is_empty())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    debug('Clone All State')
    user = clone_pass(bpf, info, PassObject())
    info.user_prog.sym_tbl = info.sym_tbl.clone()
    info.user_prog.func_dir = {}
    for func in Function.directory.values():
        new_f = func.clone(info.user_prog.func_dir)
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # NOTE: the order of generating the userspace and then BPF is important
    if not info.user_prog.graph.is_empty():
        gen_user_code(user, info, io_ctx.user_out_file)
    else:
        report("No user space program was generated. The tool has offloaded everything to BPF.")
    gen_bpf_code(bpf, info, io_ctx.bpf_out_file)
    return info


def dfs_over_deps_vars(root, visited=None):
    """
    Get organize the variables we need to share with userspace for each failure
    path.

    Recursion basis is on the length of children.

    @param root: a node of the User Program Graph
    @param visited: set of nodes already visited (we should not process a node
    twice, we should not encounter a node twice if the graph is truely a tree)

    @returns a list of set of variables dependencies along with the failure number
    """
    if visited is None:
        visited = set()
    visited.add(root)

    this_node_deps = root.paths.var_deps
    if len(root.children) == 0:
        # Base condition
        # Reaching a leaf node
        if len(root.path_ids) != 1:
            error('This was not expected!!!', root.path_ids)
            raise Exception(f'Expected the leaf to have one failure number. But it has more/less (list: {root.path_ids})')
            # return [{'vars': [], 'path_id': '-'}]
        path_id = tuple(root.path_ids)[0]
        return ({'vars': list(this_node_deps), 'path_id': path_id},)

    this_node_ids = root.path_ids.copy()
    have_it = set()
    results = []
    for child in root.children:
        if child in visited:
            error('The user graph is not a graph? a node has two parents?')
            raise Exception('Unexpected')

        # Remove the path ids that are in the children. If a path Id is not in
        # the children then the failure happens in this node (this node would
        # be the leaf for that failure path)
        this_node_ids.difference_update(child.path_ids)

        mid_res = dfs_over_deps_vars(child, visited)
        for r in mid_res:
            path_id = r['path_id']
            if path_id in have_it:
                continue
            have_it.add(path_id)
            item = {'vars': r['vars'] + list(this_node_deps), 'path_id': path_id}
            results.append(item)
    if len(this_node_ids) > 0:
        # There are some ids that are not in any of the children
        for i in this_node_ids:
            results.append({'vars': list(this_node_deps), 'path_id': i})
    return tuple(results)


def gen_user_code(user, info, out_user):
    # Switch the symbol table and functions to the snapshot suitable for
    # userspace analysis
    with info.user_prog.select_context(info):
        debug('User Prog: Handle Fallback')
        create_fallback_pass(user, info, PassObject())
        debug('~~~~~~~~~~~~~~~~~~~~~')
        debug('User Prog: Calculate Variable Deps')
        var_dependency_pass(info)
        debug('~~~~~~~~~~~~~~~~~~~~~')

        # What graph looks like
        # report_user_program_graph(info)

        # Look at var deps
        # debug(MODULE_TAG, 'Tree of variable dependencies')
        # tree = draw_tree(info.user_prog.graph, fn=lambda x: str(x.paths.var_deps))
        # debug(tree)
        # tree = draw_tree(info.user_prog.graph, fn=lambda x: str(id(x)))
        # debug(MODULE_TAG, info.user_prog.graph.paths.var_deps)
        # debug(tree)
        # tree = draw_tree(info.user_prog.graph, fn=lambda x: str(x.path_ids))
        # debug(tree)
        # ----

        meta_structs = dfs_over_deps_vars(info.user_prog.graph)
        # debug(MODULE_TAG, 'Metadata structures:', pformat(meta_structs))

        for x in meta_structs:
            state_obj = StateObject(None)
            state_obj.name = 'failure_number'
            state_obj.type_ref = BASE_TYPES[clang.TypeKind.INT]
            fields = [state_obj,]
            for var in x['vars']:
                # debug(MODULE_TAG, 'bpf/user-shared:', f'{var.name}:{var.type.spelling}')
                # TODO: do I need to clone?
                T = var.type.clone()
                state_obj = StateObject(None)
                state_obj.name = var.name
                state_obj.type_ref = T
                fields.append(state_obj)
            path_id = x['path_id']
            meta = Record(f'meta_{path_id}', fields)
            meta.is_used_in_bpf_code = True
            info.prog.add_declaration(meta)
            info.user_prog.declarations.append(meta)

            __scope = info.sym_tbl.current_scope
            info.sym_tbl.current_scope = info.sym_tbl.global_scope
            meta.update_symbol_table(info.sym_tbl)
            info.sym_tbl.current_scope = __scope
            # debug('Meta', path_id, 'at index:', len(info.user_prog.declarations))

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
    bpf = transform_vars_pass(bpf, info, PassObject())
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

    # Second transform
    debug('[2nd] Transform')
    bpf = transform_func_after_verifier(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    # Reduce number of parameters
    debug('Reduce Params')
    bpf = reduce_params_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~')

    debug('[2nd] remove everything that is not used in BPF')
    remove_everything_not_used(bpf, info, None)
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
