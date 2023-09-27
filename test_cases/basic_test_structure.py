import sys
import os
import clang.cindex as clang

current_file_dir = os.path.dirname(__file__)
code_under_test_dir = os.path.join(current_file_dir, '../src/')

sys.path.insert(0, code_under_test_dir)
from utility import parse_file, find_elem
from sym_table_gen import build_sym_table
from understand_logic import gather_instructions_under

from data_structure import Info
from instruction import BODY

class BasicTest:
    def __init__(self, file_path, entry_func_name, compiler_args=''):
        self.file_path = file_path
        self.entry_func_name = entry_func_name
        self.compiler_args = compiler_args
        self.info = None

    def run_test(self):
        # Create info object
        self.info = Info()
        self.info.entry_func_name = self.entry_func_name
        # This is the AST generated with Clang
        index, tu, cursor = parse_file(self.file_path, self.compiler_args)
        # Collect information about classes, functions, variables, ...
        build_sym_table(cursor, self.info)
        # Find the entry function
        entry_func = find_elem(cursor, self.entry_func_name)[0]
        if entry_func is None:
            error('Did not found the entry function')
            return

        with self.info.sym_tbl.with_func_scope(self.entry_func_name):
            # Gather the instructions
            body_of_loop = list(entry_func.get_children())[-1]
            assert body_of_loop.kind == clang.CursorKind.COMPOUND_STMT
            # Convert cursors to instruction objects
            insts = gather_instructions_under(body_of_loop, self.info, BODY)
            self.test(insts)

    def test(self, insts):
        raise Exception('No tests')
