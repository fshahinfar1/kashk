import sys
import os
import clang.cindex as clang

current_file_dir = os.path.dirname(__file__)
code_under_test_dir = os.path.join(current_file_dir, '../src/')

sys.path.insert(0, code_under_test_dir)
from utility import parse_file, find_elem
from sym_table_gen import build_sym_table
from understand_logic import gather_instructions_under
from understand_logic_handler import create_func_objs

from data_structure import Info, Function
from instruction import BODY
from framework_support import InputOutputContext
from bpf import SK_SKB_PROG

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
        # Find the entry function
        entry_func = find_elem(cursor, self.info.io_ctx.entry_func)[0]
        if entry_func is None:
            error('Did not found the entry function')
            return

        with self.info.sym_tbl.with_func_scope(self.info.io_ctx.entry_func):
            # Gather the instructions
            body_of_loop = list(entry_func.get_children())[-1]
            assert body_of_loop.kind == clang.CursorKind.COMPOUND_STMT
            # Convert cursors to instruction objects
            insts = gather_instructions_under(body_of_loop, self.info, BODY)
            create_func_objs(self.info)
            self.test(insts)

    def test(self, insts):
        raise Exception('No tests')
