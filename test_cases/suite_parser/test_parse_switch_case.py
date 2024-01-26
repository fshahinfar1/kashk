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




class TestCase(BasicTest):
    def test(self, insts):
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        # Generate the code and show it for debuging
        text, _ = gen_code(bpf, self.info)
        print(text)
        # show_insts([bpf])

        cases = find_elems_of_kind(insts, clang.CursorKind.CASE_STMT)

        assert len(cases) == 9, f'Expected 7 is {len(cases)}'
        condition_1  = cases[0].case.children[0]
        assert condition_1.kind == clang.CursorKind.INTEGER_LITERAL
        assert condition_1.text == '1'
        assert cases[0].body.has_children()
        body_2 = cases[1].body.get_children()
        assert len(body_2) == 3, 'Failed to associated the children of case body to the instruction'

        case = cases[-1]
        assert case.body.children[0].kind == clang.CursorKind.BINARY_OPERATOR, 'Last case statement should have body'
        case = cases[-2]
        assert not case.body.has_children(), 'The one before last should not have body'

        print('parsing switch case Test: Okay')



if __name__ == '__main__':
    input_files_dir = os.path.join(curdir, '../inputs/')
    file_path = os.path.join(input_files_dir, 'switch_case.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
