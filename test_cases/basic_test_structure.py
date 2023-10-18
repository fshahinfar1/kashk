import sys
import os
import clang.cindex as clang

current_file_dir = os.path.dirname(__file__)
code_under_test_dir = os.path.join(current_file_dir, '../src/')

sys.path.insert(0, code_under_test_dir)
from utility import parse_file, find_elem
from sym_table_gen import build_sym_table
from understand_logic import gather_instructions_under
from understand_logic_handler import create_func_objs, add_known_func_objs

from data_structure import Info, Function
from instruction import BODY
from framework_support import InputOutputContext
from bpf import SK_SKB_PROG

from offload import load_other_sources, BPF_MAIN
from find_ev_loop import get_entry_code
from sym_table import Scope

class BasicTest:
    def __init__(self, file_path, entry_func_name, compiler_args='', hook='sk_skb'):
        io_ctx = InputOutputContext()
        io_ctx.set_input(file_path)
        io_ctx.set_entry_func(entry_func_name)
        io_ctx.set_cflags(compiler_args)
        io_ctx.bpf_hook = hook
        self.info = Info.from_io_ctx(io_ctx)

    def run_test(self):
        # This is the AST generated with Clang
        index, tu, cursor = parse_file(self.info.io_ctx.input_file, self.info.io_ctx.cflags)
        # Collect information about classes, functions, variables, ...
        build_sym_table(cursor, self.info)
        # Load other source files
        load_other_sources(self.info.io_ctx, self.info)
        # Select the main scope
        scope = Scope(self.info.sym_tbl.global_scope)
        self.info.sym_tbl.scope_mapping[BPF_MAIN] = scope
        self.info.sym_tbl.current_scope = scope
        # Find the entry function
        main = get_entry_code(cursor, self.info)
        assert main is not None
        # Convert cursors to instruction objects
        insts = gather_instructions_under(main, self.info, BODY)
        create_func_objs(self.info)
        add_known_func_objs(self.info)
        self.test(insts)

    def test(self, insts):
        raise Exception('No tests')
