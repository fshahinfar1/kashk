import os
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
sys.path.insert(0, root_dir)
from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from utility import show_insts
from data_structure import *
from instruction import *
from sym_table import *

from passes.pass_obj import PassObject
from passes.linear_code import linear_code_pass


class TestCase(BasicTest):
    def test(self, insts):
        # Get ready for a pass
        third_arg = PassObject()
        bpf = Block(BODY)
        bpf.extend_inst(insts)
        # Move function calls out of the ARG context!
        bpf = linear_code_pass(bpf, self.info, third_arg)

        # Generate the code and show it for debuging
        # text, _ = gen_code(bpf, self.info)
        # print(text)

        # Check the pass is correct
        has_var_declare = False
        has_var_assignment = False
        has_function_move = False
        # TODO: Check the inner function movement
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
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'linear_pass.cpp')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
