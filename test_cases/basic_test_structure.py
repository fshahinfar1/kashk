import sys
import os
import clang.cindex as clang

current_file_dir = os.path.dirname(__file__)
code_under_test_dir = os.path.join(current_file_dir, '../src/')

sys.path.insert(0, code_under_test_dir)
from utility import parse_file, find_elem
from sym_table_gen import build_sym_table
from parser.understand_logic import gather_instructions_under
from parser.understand_logic_handler import (create_func_objs,
        add_known_func_objs)

from data_structure import Info, Function
from instruction import BODY
from framework_support import InputOutputContext

from offload import _prepare_event_handler_args, MAIN
from parser.find_ev_loop import get_entry_code
from sym_table import Scope


class BasicTest:
    def __init__(self, file_path, entry_func_name, compiler_args='', hook='sk_skb'):
        io_ctx = InputOutputContext()
        io_ctx.set_input(file_path)
        io_ctx.set_entry_func(entry_func_name)
        io_ctx.set_cflags(compiler_args)
        io_ctx.bpf_hook = hook
        io_ctx.set_framework('poll')
        self.info = Info.from_io_ctx(io_ctx)

    def run_test(self):
        # This is the AST generated with Clang
        index, tu, cursor = parse_file(self.info.io_ctx.input_file, self.info.io_ctx.cflags)
        # Collect information about classes, functions, variables, ...
        build_sym_table(cursor, self.info)
        # Find the entry function
        main, entry_func = get_entry_code(cursor, self.info)
        assert main is not None
        # Convert cursors to instruction objects
        insts = gather_instructions_under(main, self.info, BODY)
        create_func_objs(self.info)
        add_known_func_objs(self.info)
        prepare_insts = _prepare_event_handler_args(cursor, self.info)
        insts = prepare_insts + insts
        self.test(insts)

    def test(self, insts):
        raise Exception('No tests')
