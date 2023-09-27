import sys
import os
import clang.cindex as clang

current_file_dir = os.path.dirname(__file__)
code_under_test_dir = os.path.join(current_file_dir, '../src/')
input_files_dir = os.path.join(current_file_dir, './inputs/')

sys.path.insert(0, code_under_test_dir)
from sym_table import *
from data_structure import *
from instruction import *
from utility import parse_file, find_elem, show_insts
from sym_table_gen import build_sym_table
from understand_logic import gather_instructions_under
from bpf_code_gen import gen_code

from passes.pass_obj import PassObject
from passes.linear_code import linear_code_pass


def run_test():
    file_path = os.path.join(input_files_dir, 'lib_types.c')
    entry_func_name = 'main'
    compiler_args = ''

    # Create info object
    info = Info()
    info.entry_func_name = entry_func_name
    # This is the AST generated with Clang
    index, tu, cursor = parse_file(file_path, compiler_args)
    # Collect information about classes, functions, variables, ...
    build_sym_table(cursor, info)
    # Find the entry function
    entry_func = find_elem(cursor, entry_func_name)[0]
    if entry_func is None:
        error('Did not found the entry function')
        return

    with info.sym_tbl.with_func_scope(entry_func_name):
        # Gather the instructions
        body_of_loop = list(entry_func.get_children())[-1]
        assert body_of_loop.kind == clang.CursorKind.COMPOUND_STMT
        # Convert cursors to instruction objects
        insts = gather_instructions_under(body_of_loop, info, BODY)

        third_arg = PassObject()
        bpf = Block(BODY)
        bpf.extend_inst(insts)
        # Move function calls out of the ARG context!
        # bpf = linear_code_pass(bpf, info, third_arg)

        # Generate the code and show it for debuging
        text, _ = gen_code(bpf, info)
        print(text)

        show_insts(insts)
        # truth = [ ]
        # for inst in insts:
        #     print(inst)

        print('Library Type Test: Okay')



if __name__ == '__main__':
    run_test()
