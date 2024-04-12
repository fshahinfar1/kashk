import clang.cindex as clang
from pprint import pformat, pprint

from framework_support import InputOutputContext
from log import *
from data_structure import *
from instruction import *
from utility import (parse_file, find_elem, report_user_program_graph,
        draw_tree, find_elems_of_kind)
from parser.find_ev_loop import get_entry_code
from sym_table import Scope
from sym_table_gen import build_sym_table
from parser.understand_logic import  (gather_instructions_from,
        get_variable_declaration_before_elem)
from parser.understand_logic_handler import create_func_objs, add_known_func_objs

from code_gen import generate_bpf_prog, gen_code
from user import generate_user_prog

from passes.pass_obj import PassObject
from passes.mark_relevant_code import mark_relevant_code
from passes.primary_annotation_pass import primary_annotation_pass
from passes.mark_io import mark_io
from passes.clone import clone_pass
from passes.simplify_code import simplify_code_structure
from passes.create_failure_path import create_failure_paths
from passes.find_unused_vars import remove_unused_args
from passes.fallback_variables import failure_path_fallback_variables
from passes.create_meta_struct import create_fallback_meta_structure, FAILURE_NUMBER_FIELD
from passes.update_original_ref import update_original_ast_references
from passes.update_func_signature import update_function_signature
from passes.update_func_failure_status import update_function_failure_status

from passes.bpf_passes.loop_end import loop_end_pass
from passes.bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from passes.bpf_passes.transform_vars import transform_vars_pass
from passes.bpf_passes.userspace_fallback import userspace_fallback_pass
from passes.bpf_passes.verifier import verifier_pass
from passes.bpf_passes.transform_after_verifier import transform_func_after_verifier
from passes.bpf_passes.reduce_params import reduce_params_pass
from passes.bpf_passes.remove_everything_not_used import remove_everything_not_used
from passes.bpf_passes.prog_complexity import mitiage_program_comlexity
from passes.bpf_passes.change_bpf_loop import change_to_bpf_loop
from passes.bpf_passes.rewrite_while_loop import rewrite_while_loop

from helpers.instruction_helper import decl_new_var, show_insts, INT
from helpers.ast_graphviz import ASTGraphviz
from helpers.cfg_graphviz import CFGGraphviz

from brain.cost_func import set_context_switch_cost

from perf_model.static_high_level_perf_model import gen_static_high_level_perf_model
from cfg import make_cfg, HTMLWriter
from decide import analyse_offload


MODULE_TAG = '[Gen Offload]'
MAIN = '[[main]]'


def _print_code(prog, info):
    text, _ =  gen_code(prog, info)
    debug('code:\n', text, '\n---', sep='', tag=MODULE_TAG)


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
            # the sk_state_scope is the per connection scope
            # This is crazy. Why did I not fix this before. I should correct it

            # NOTE: the arguments of the event handler function are put on a
            # map for future access (connection context)
            assert not arg.type_ref.is_pointer(), 'Putting a pointer on the shared map is incorrect'
            info.sym_tbl.sk_state_scope.insert_entry(arg.name,
                    arg.type_ref, clang.CursorKind.PARM_DECL, None)
    # No instructions to be added
    return []


def move_vars_before_event_loop_to_shared_scope(entry_func, main, info):
    list_vars = get_variable_declaration_before_elem(entry_func, main)
    # if list_vars:
    #     debug('This is the list of variables before event loop:', tag=MODULE_TAG)
    #     debug(tuple(map(lambda x: f'{x.name}:{x.type.spelling}', list_vars)), tag=MODULE_TAG)
    #     debug('-------------------------------------------------', tag=MODULE_TAG)
    for var in list_vars:
        var.update_symbol_table(info.sym_tbl.shared_scope)


def prepare_userspace_fallback(prog, info):
    debug('Create Failure Paths', tag=MODULE_TAG)
    create_failure_paths(prog, info, None)
    # for pid, path in info.failure_paths.items():
    #     txt, _ = gen_code(path, info)
    #     debug(pid, ':\n', txt, tag=MODULE_TAG)
    #     debug('~~~')
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Juggle function directory ---------------------------
    tmp_fn_dir = Function.directory
    Function.directory = info.original_ast
    # Move failure functions to the original_ast list
    for f in info.failure_path_new_funcs:
        assert f.name not in Function.directory, 'We are adding failure functions to the original ast, one of them were already here ?!'
        Function.directory[f.name] = f
        # f.clone(info.original_ast)
        # print(f.name, f.args)
    # -----------------------------------------------------

    # Some checks for failure paths -----------------------
    # pprint(info.failure_paths)
    for pid, path in info.failure_paths.items():
        for call in find_elems_of_kind(path, clang.CursorKind.CALL_EXPR):
            f = call.get_function_def()
            # f = info.original_ast.get(call.name)
            assert len(call.args) == len(f.args), f'{pid} @{f.name}:\nfunc: {str(f.args) }\ncall: {str(call.args)}'
    debug('number of failure paths:', len(info.failure_paths), tag=MODULE_TAG)
    # -----------------------------------------------------

    debug('Remove Unused Args From Failure Functions', tag=MODULE_TAG)
    remove_unused_args(prog, info, None)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Failure Path Variables', tag=MODULE_TAG)
    failure_path_fallback_variables(info)

    for pid, V in info.failure_vars.items():
        ignore = False
        for var in V:
            T = var.type
            if T.is_pointer() and not var.is_bpf_ctx:
                # debug('not doing path:', pid, 'because:', var)
                ignore = True

        if not ignore:
            continue
        info.failure_paths[pid] = [Literal('/* from begining */', CODE_LITERAL),]
        info.failure_vars[pid].clear()

        tbl = info.sym_tbl
        for scope in tbl.scope_mapping.scope_mapping.values():
            for e in scope.symbols.values():
                if pid in e.is_fallback_var:
                    e.is_fallback_var.remove(pid)
    # pprint(info.failure_vars)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Create Fallback Meta Structures', tag=MODULE_TAG)
    create_fallback_meta_structure(info)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Juggle function directory ---------------------------
    for f in Function.directory.values():
        other_f = tmp_fn_dir.get(f.name)
        if other_f is None:
            continue
        other_f.path_ids = set(f.path_ids)
    Function.directory = tmp_fn_dir
    # -----------------------------------------------------
    return prog


def generate_offload(io_ctx):
    """
    Main logic of the compiler. It defines the order of passes that are needed.
    """
    # filter_log(MODULE_TAG, '[Select Userspace Pass]', '[Var Dependency]')
    # filter_log(MODULE_TAG, '[Var Dependency]', '[Create Fallback]',
    #         '[User Code]', '[Select Userspace]')

    info = Info.from_io_ctx(io_ctx)
    # Parse source files
    index, tu, cursor = parse_file(info.io_ctx.input_file, io_ctx.cflags)
    build_sym_table(cursor, info)
    # Find the entry function
    main, entry_func = get_entry_code(cursor, info)
    #
    move_vars_before_event_loop_to_shared_scope(entry_func, main, info)

    # Start the passes
    debug('First pass on the AST (initializing...)', tag=MODULE_TAG)
    insts = gather_instructions_from(main, info, BODY)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Gather Infromation About Functions', tag=MODULE_TAG)
    create_func_objs(info)
    add_known_func_objs(info)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    prepare_insts = _prepare_event_handler_args(cursor, info)

    # We have our own AST now, continue processing ...
    prog = Block(BODY)
    prog.extend_inst(prepare_insts)
    prog.extend_inst(insts)

    # Mark which type or func definitions should be placed in generated code
    debug('Mark relevant code', tag=MODULE_TAG)
    mark_relevant_code(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('[1st] Annotation', tag=MODULE_TAG)
    prog = primary_annotation_pass(prog, info, None)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # TODO: I do not like this, because it resulted in maintaining two function
    # directories. Maybe if we rename the function so we have bpf and userspace
    # version of the function with different names the reference management
    # become easier. At least it would be obviouse which version of the
    # function we want to access.
    debug('Clone the original code', tag=MODULE_TAG)
    update_original_ast_references(prog, info, None)
    # Store the original version of the source code (unchanged) for future use
    tmp_fn_dir = {}
    for k, f in Function.directory.items():
        f.clone(tmp_fn_dir)
    tmp_f = Function(MAIN, None, tmp_fn_dir)
    tmp_f.body = prog
    info.original_ast = tmp_fn_dir
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Mark Read/Write Inst & Buf', tag=MODULE_TAG)
    mark_io(prog, info)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Simplify Code', tag=MODULE_TAG)
    prog = simplify_code_structure(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Feasibility Analysis', tag=MODULE_TAG)
    prog = feasibilty_analysis_pass(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # End event loop with packet drop
    debug('Loop End', tag=MODULE_TAG)
    prog = loop_end_pass(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Rewrite While/Do-While', tag=MODULE_TAG)
    prog = rewrite_while_loop(prog, info, None)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # debug('Change loop to bpf_loop', tag=MODULE_TAG)
    # prog = change_to_bpf_loop(prog, info, None)
    # debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('[1st] Update Function Signature', tag=MODULE_TAG)
    prog = update_function_signature(prog, info)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Transform access to variables and read/write buffers.
    debug('Transform Vars', tag=MODULE_TAG)
    prog = transform_vars_pass(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Verifier
    debug('[1st] Verifier', tag=MODULE_TAG)
    prog = verifier_pass(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Second transform
    debug('Transform: Part II', tag=MODULE_TAG)
    prog = transform_func_after_verifier(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Verifier
    debug('[2nd] Verifier', tag=MODULE_TAG)
    with log_silent():
        prog = verifier_pass(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # prepare_userspace_fallback(prog, info)

    debug('Update Function Failure Status', tag=MODULE_TAG)
    update_function_failure_status(prog, info, None)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # NOTE: since I do not care about sharing data with userspace, lets just
    # mark each function that fails with the failure path number one
    for f in Function.directory.values():
        if not f.is_used_in_bpf_code or not f.may_fail:
            continue
        f.path_ids.add(1)
        # print(f.name)

    debug('[2nd] Update Function Signature', tag=MODULE_TAG)
    prog = update_function_signature(prog, info)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Handle moving to userspace and removing the instruction not possible in
    # BPF
    debug('Userspace Fallback', tag=MODULE_TAG)
    prog = userspace_fallback_pass(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Reduce number of parameters
    debug('Reduce Params', tag=MODULE_TAG)
    prog = reduce_params_pass(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('[2nd] remove everything that is not used in BPF', tag=MODULE_TAG)
    prog = remove_everything_not_used(prog, info, None)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Verifier
    debug('[3rd] Verifier', tag=MODULE_TAG)
    with log_silent():
        prog = verifier_pass(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # debug('Program Complexity Pass', tag=MODULE_TAG)
    # list_bpf_progs = mitiage_program_comlexity(prog, info, None)
    # debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # TODO: split the code between parser and verdict
    debug('[Parser/Verdict Split Code]', tag=MODULE_TAG)
    info.prog.set_code(prog)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('[Decide What to Offload]', tag=MODULE_TAG)
    # analyse_offload(prog, info)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Write the code we have generated
    debug('Write BPF Code', tag=MODULE_TAG)
    text = generate_bpf_prog(info)
    with open(io_ctx.bpf_out_file, 'w') as f:
        f.write(text)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Check for the userspace code
    if info.failure_paths and len(info.failure_paths) > 0:
        gen_user_code(info, io_ctx.user_out_file)
    else:
        report("No user space program was generated. The tool has offloaded everything to BPF.")

    return info


def gen_user_code(info, out_user):
    """
    Generate the userspace program code from the prepared Info object.
    """
    decl = []
    failure_num = decl_new_var(INT, info, decl, FAILURE_NUMBER_FIELD)
    switch = ControlFlowInst.build_switch(failure_num)
    for path_id, path in info.failure_paths.items():
        case_stmt = CaseSTMT(None)
        case_stmt.case.add_inst(Literal(str(path_id), clang.CursorKind.INTEGER_LITERAL))
        case_stmt.body.extend_inst(path)
        brk = Instruction.build_break_inst()
        case_stmt.body.add_inst(brk)
        switch.body.add_inst(case_stmt)
    main = Block(BODY)
    main.add_inst(switch)
    text = generate_user_prog(main, info)
    with open(out_user, 'w') as f:
        f.write(text)
