import clang.cindex as clang
from pprint import pformat

from framework_support import InputOutputContext
from log import *
from data_structure import *
from instruction import *
from utility import (parse_file, find_elem, report_user_program_graph,
        draw_tree)
from parser.find_ev_loop import get_entry_code
from sym_table import Scope
from sym_table_gen import build_sym_table, process_source_file
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
from passes.find_unused_vars import find_unused_vars
from passes.fallback_variables import failure_path_fallback_variables
from passes.create_meta_struct import create_fallback_meta_structure, FAILURE_NUMBER_FIELD
from passes.update_original_ref import update_original_ast_references

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
BPF_MAIN = 'MAIN_SCOPE'


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
            # the global_scope is the per connection scope
            # This is crazy. Why did I not fix this before. I should correct it

            # NOTE: the arguments of the event handler function are put on a
            # map for future access (connection context)
            assert not arg.type_ref.is_pointer(), 'Putting a pointer on the shared map is incorrect'
            info.sym_tbl.shared_scope.insert_entry(arg.name,
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


def load_other_sources(io_ctx, info):
    # This is the AST generated with Clang
    others = []
    for path in io_ctx.other_source_files:
        report('Load:', path)
        _, _, other_cursor = parse_file(path, io_ctx.cflags)
        others.append(other_cursor)
        process_source_file(other_cursor, info)


def generate_offload(io_ctx):
    # filter_log(MODULE_TAG, '[Select Userspace Pass]', '[Var Dependency]')
    # filter_log(MODULE_TAG, '[Var Dependency]', '[Create Fallback]',
    #         '[User Code]', '[Select Userspace]')

    info = Info.from_io_ctx(io_ctx)
    build_sym_table(info)
    # Parse source files
    index, tu, cursor = parse_file(info.io_ctx.input_file, io_ctx.cflags)
    process_source_file(cursor, info)
    load_other_sources(io_ctx, info)
    # Build and select the entry function scope
    scope = Scope(info.sym_tbl.global_scope)
    info.sym_tbl.scope_mapping[BPF_MAIN] = scope
    info.sym_tbl.current_scope = scope
    info.prog.add_args_to_scope(scope)
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

    update_original_ast_references(prog, info, None)
    info.original_ast = { k: v for k, v in Function.directory.items() if v.is_used_in_bpf_code }
    info.original_ast['[[main]]'] =  prog

    debug('Mark Read/Write Inst & Buf', tag=MODULE_TAG)
    mark_io(prog, info)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Simplify Code', tag=MODULE_TAG)
    prog = simplify_code_structure(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Feasibility Analysis', tag=MODULE_TAG)
    prog = feasibilty_analysis_pass(prog, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # debug('Clone All State', tag=MODULE_TAG)
    # user = clone_pass(prog, info, PassObject())
    # info.user_prog.sym_tbl = info.sym_tbl.clone()
    # info.user_prog.func_dir = {}
    # for func in Function.directory.values():
    #     new_f = func.clone(info.user_prog.func_dir)
    # debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    prog = gen_bpf_code(prog, info, io_ctx.bpf_out_file)
    # if len(info.failure_paths) > 0:
    #     gen_user_code(info, io_ctx.user_out_file)
    # else:
    #     report("No user space program was generated. The tool has offloaded everything to BPF.")

    return info


def gen_user_code(info, out_user):
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


def gen_bpf_code(bpf, info, out_bpf):
    # End event loop with packet drop
    debug('Loop End', tag=MODULE_TAG)
    bpf = loop_end_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Rewrite While/Do-While', tag=MODULE_TAG)
    bpf = rewrite_while_loop(bpf, info, None)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # debug('Change loop to bpf_loop', tag=MODULE_TAG)
    # bpf = change_to_bpf_loop(bpf, info, None)
    # debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Transform access to variables and read/write buffers.
    debug('Transform Vars', tag=MODULE_TAG)
    bpf = transform_vars_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Verifier
    debug('Verifier', tag=MODULE_TAG)
    bpf = verifier_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Second transform
    debug('[2nd] Transform', tag=MODULE_TAG)
    bpf = transform_func_after_verifier(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Verifier
    debug('[2nd] Verifier', tag=MODULE_TAG)
    bpf = verifier_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Reduce number of parameters
    debug('Reduce Params', tag=MODULE_TAG)
    bpf = reduce_params_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Create Failure Paths', tag=MODULE_TAG)
    create_failure_paths(bpf, info, None)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # debug('Remove Unused Args From Failure Functions', tag=MODULE_TAG)
    # # TODO: Remove unused args from failure functions
    # for func in info.failure_path_new_funcs:
    #     tmp_names = set(a.name for a in func.args)
    #     unused_vars = find_unused_vars(func.body, info, target=tmp_names)
    #     for a in func.args:
    #         if a.name in unused_vars:
    #             a.set_unused()
    # debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Failure Path Variables', tag=MODULE_TAG)
    failure_path_fallback_variables(info)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('Create Fallback Meta Structures', tag=MODULE_TAG)
    create_fallback_meta_structure(info)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # # TODO: Update the userspace fallback with new implementation of failure
    # # paths
    # Handle moving to userspace and removing the instruction not possible in
    # BPF
    # debug('Userspace Fallback', tag=MODULE_TAG)
    # bpf = userspace_fallback_pass(bpf, info, PassObject())
    # debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('[2nd] remove everything that is not used in BPF', tag=MODULE_TAG)
    remove_everything_not_used(bpf, info, None)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Verifier
    debug('[3rd] Verifier', tag=MODULE_TAG)
    bpf = verifier_pass(bpf, info, PassObject())
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # debug('Program Complexity Pass', tag=MODULE_TAG)
    # list_bpf_progs = mitiage_program_comlexity(bpf, info, None)
    # debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # TODO: split the code between parser and verdict
    debug('[Parser/Verdict Split Code]', tag=MODULE_TAG)
    info.prog.set_code(bpf)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    debug('[Decide What to Offload]', tag=MODULE_TAG)
    analyse_offload(bpf, info)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)

    # Write the code we have generated
    debug('BPF Code Generation', tag=MODULE_TAG)
    text = generate_bpf_prog(info)
    with open(out_bpf, 'w') as f:
        f.write(text)
    debug('~~~~~~~~~~~~~~~~~~~~~', tag=MODULE_TAG)
    return bpf
