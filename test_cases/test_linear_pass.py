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
from utility import parse_file, find_elem
from sym_table_gen import build_sym_table
from understand_logic import gather_instructions_under
from bpf_code_gen import gen_code

from passes.pass_obj import PassObject
from passes.linear_code import linear_code_pass


def run_test():
    file_path = os.path.join(input_files_dir, 'linear_pass.cpp')
    entry_func_name = 'main'

    # Create info object
    info = Info()
    info.entry_func_name = entry_func_name
    # This is the AST generated with Clang
    index, tu, cursor = parse_file(file_path)
    # Collect information about classes, functions, variables, ...
    build_sym_table(cursor, info)
    # Find the entry function
    entry_func = find_elem(cursor, entry_func_name)
    if entry_func is None:
        error('Did not found the entry function')
        return

    with info.sym_tbl.with_func_scope(entry_func_name):
        # Gather the instructions
        body_of_loop = list(entry_func.get_children())[-1]
        insts = gather_instructions_under(body_of_loop, info, BODY)
        # Get ready for a pass
        third_arg = PassObject()
        bpf = Block(BODY)
        bpf.extend_inst(insts)
        # Move function calls out of the ARG context!
        bpf = linear_code_pass(bpf, info, third_arg)

        # Generate the code and show it for debuging
        # text, _ = gen_code(bpf, info)
        # print(text)

        # Check the pass is correct
        has_var_declare = False
        has_var_assignment = False
        has_function_move = False
        function_assigned_to_var = '__not_set__' 
        for i in bpf.get_children():
            if i.kind == clang.CursorKind.VAR_DECL:
                if i.name == 'test' and not i.init.has_children():
                    has_var_declare = True
            if i.kind == clang.CursorKind.BINARY_OPERATOR:
                if i.op == '=':
                    rhs = i.rhs.get_children()[0]
                    if rhs.kind == clang.CursorKind.CALL_EXPR and rhs.name == 'f1':
                        lhs = i.lhs.get_children()[0]
                        if lhs.kind == clang.CursorKind.DECL_REF_EXPR:
                            function_assigned_to_var = lhs.name
                            if function_assigned_to_var == 'test':
                                has_var_assignment = True
            if i.kind == clang.CursorKind.SWITCH_STMT:
                c = i.cond.get_children()
                assert len(c) == 1
                if c[0].kind == clang.CursorKind.DECL_REF_EXPR:
                    if c[0].name == function_assigned_to_var:
                        has_function_move = True

        assert has_var_declare
        assert has_var_assignment
        assert has_function_move
        print('Linear Pass Test: Okay')



if __name__ == '__main__':
    run_test()
