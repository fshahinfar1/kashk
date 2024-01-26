import os
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
sys.path.insert(0, root_dir)
from basic_test_structure import BasicTest, current_file_dir

from code_gen import gen_code
from utility import find_elems_of_kind
from helpers.instruction_helper import show_insts
from data_structure import *
from instruction import *
from sym_table import *

from passes.pass_obj import PassObject
from passes.simplify_code import simplify_code_structure
from passes.bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from passes.bpf_passes.mark_user_boundary import get_number_of_failure_paths


class TestCase(BasicTest):
    def test(self, insts):
        info = self.info
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        func = Function.directory['fancy']
        # Generate the code and show it for debuging
        text, _ = gen_code(func.body, self.info)
        # print(text)
        # show_insts([func.body,])

        # Tests
        if_stmt_list = find_elems_of_kind(func.body, clang.CursorKind.IF_STMT)
        assert len(if_stmt_list) > 0
        if_stmt = if_stmt_list[0]
        if_cond = if_stmt.cond.children[0]
        assert if_cond.kind == clang.CursorKind.BINARY_OPERATOR, "The parser has failed to parse the macro correctly"

        print('Parse Macro Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/parser')
    file_path = os.path.join(input_files_dir, 'macro.c')
    entry_func_name = 'main'
    compiler_args = ''
    hook = 'sk_skb'
    test = TestCase(file_path, entry_func_name, compiler_args, hook)
    test.run_test()

