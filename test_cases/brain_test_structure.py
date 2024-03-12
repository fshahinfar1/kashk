import os
import subprocess
import clang.cindex as clang
from basic_test_structure import BasicTest
from utility import parse_file, find_elem
from sym_table_gen import build_sym_table, process_source_file
from parser.understand_logic import gather_instructions_under
from parser.understand_logic_handler import create_func_objs, add_known_func_objs

from data_structure import *
from instruction import BODY, Block
from framework_support import InputOutputContext

from offload import (load_other_sources, _prepare_event_handler_args,
        move_vars_before_event_loop_to_shared_scope, BPF_MAIN)
from parser.find_ev_loop import get_entry_code
from sym_table import Scope

from passes.pass_obj import PassObject
from passes.mark_relevant_code import mark_relevant_code
from passes.primary_annotation_pass import primary_annotation_pass
from passes.mark_io import mark_io
from passes.clone import clone_pass
from passes.simplify_code import simplify_code_structure
from passes.create_failure_path import create_failure_paths
from passes.find_unused_vars import find_unused_vars
from passes.fallback_variables import failure_path_fallback_variables
from passes.create_meta_struct import create_fallback_meta_structure
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

from helpers.instruction_helper import show_insts
from helpers.ast_graphviz import ASTGraphviz
from helpers.cfg_graphviz import CFGGraphviz

from decide import analyse_offload
from user import generate_user_prog
from code_gen import generate_bpf_prog


curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
script_dir = os.path.abspath(os.path.join(root_dir, '../compile_scripts'))


class BrainTest(BasicTest):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cfg_table = None

    @property
    def main_cfg(self):
        return self.cfg_table['__main__']

    def show_cfg(self, cfg):
        tmp = CFGGraphviz.do(cfg, self.info)
        # tmp.dot.save('/tmp/test_cfg.dot')
        tmp.dot.render(filename='test_cfg', directory='/tmp/', format='svg')

    def gen_code(self):
        info = self.info
        out_user = '/tmp/test_user.c'
        out_bpf  = '/tmp/test_bpf.c'
        with info.user_prog.select_context(info):
            text = generate_user_prog(info)
        with open(out_user, 'w') as f:
            f.write(text)
        text = generate_bpf_prog(info)
        with open(out_bpf, 'w') as f:
            f.write(text)
        # Try to compile the user <-- This will fail unfortunately
        # ...
        # Try to compile the BPF
        bpf_bin_out = '/tmp/test_bpf.o'
        compile_script = os.path.join(script_dir, 'compile_bpf_source.sh')
        cmd = ['/bin/bash', compile_script, out_bpf, bpf_bin_out]
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ret = proc.returncode
        assert ret == 0, f'The generated source code should compile (ret code: {ret})'

        return [out_bpf, out_user]

    def _gen_user_code(self, user):
        info = self.info
        with info.user_prog.select_context(info):
            create_fallback_pass(user, info, PassObject())
            var_dependency_pass(info)
            meta_structs = dfs_over_deps_vars(info.user_prog.graph)
            for x in meta_structs:
                state_obj = StateObject(None)
                state_obj.name = 'failure_number'
                state_obj.type_ref = BASE_TYPES[clang.TypeKind.INT]
                fields = [state_obj,]
                for var in x['vars']:
                    T = var.type.clone()
                    state_obj = StateObject(None)
                    state_obj.name = var.name
                    state_obj.type_ref = T
                    fields.append(state_obj)
                path_id = x['path_id']
                meta = Record(f'meta_{path_id}', fields)
                meta.is_used_in_bpf_code = True
                info.prog.add_declaration(meta)
                info.user_prog.declarations[path_id] = meta
                __scope = info.sym_tbl.current_scope
                info.sym_tbl.current_scope = info.sym_tbl.global_scope
                meta.update_symbol_table(info.sym_tbl)
                info.sym_tbl.current_scope = __scope


    def _gen_bpf_code(self, bpf):
        info = self.info
        bpf = loop_end_pass(bpf, info, PassObject())
        bpf = transform_vars_pass(bpf, info, PassObject())
        bpf = userspace_fallback_pass(bpf, info, PassObject())
        bpf = verifier_pass(bpf, info, PassObject())
        bpf = transform_func_after_verifier(bpf, info, PassObject())
        bpf = reduce_params_pass(bpf, info, PassObject())
        remove_everything_not_used(bpf, info, None)
        # bpf = change_to_bpf_loop(bpf, info, None)
        # list_bpf_progs = mitiage_program_comlexity(bpf, info, None)
        info.prog.set_code(bpf)
        cfg_table = analyse_offload(bpf, info)
        self.cfg_table = cfg_table
        return bpf

    def run_test(self):
        info = self.info
        # This is the AST generated with Clang
        index, tu, cursor = parse_file(info.io_ctx.input_file,
                                                    info.io_ctx.cflags)
        # Collect information about classes, functions, variables, ...
        build_sym_table(info)
        process_source_file(cursor, info)
        # Load other source files
        load_other_sources(info.io_ctx, info)
        # Select the main scope
        scope = Scope(info.sym_tbl.global_scope)
        info.sym_tbl.scope_mapping[BPF_MAIN] = scope
        info.sym_tbl.current_scope = scope
        info.prog.add_args_to_scope(scope)
        # Find the entry function
        main, entry_func = get_entry_code(cursor, info)
        assert main is not None
        move_vars_before_event_loop_to_shared_scope(entry_func, main, info)
        # Convert cursors to instruction objects
        insts = gather_instructions_under(main, info, BODY)
        create_func_objs(info)
        add_known_func_objs(info)
        prepare_insts = _prepare_event_handler_args(cursor, info)
        # Form the program AST
        prog = Block(BODY)
        prog.extend_inst(prepare_insts)
        prog.extend_inst(insts)
        # Passes
        mark_relevant_code(prog, info, PassObject())
        prog = primary_annotation_pass(prog, info, None)
        mark_io(prog, info)
        prog = simplify_code_structure(prog, info, PassObject())
        prog = feasibilty_analysis_pass(prog, info, PassObject())
        create_failure_paths(prog, info, None)
        failure_path_fallback_variables(info)
        create_fallback_meta_structure(info)
        prog = self._gen_bpf_code(prog)
        self.test(prog)
