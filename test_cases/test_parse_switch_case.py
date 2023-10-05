import os
from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from utility import show_insts, find_elems_of_kind
from data_structure import *
from instruction import *
from sym_table import *


class TestCase(BasicTest):
    def test(self, insts):
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        # Generate the code and show it for debuging
        # text, _ = gen_code(bpf, self.info)
        # print(text)

        cases = find_elems_of_kind(insts, clang.CursorKind.CASE_STMT)

        assert len(cases) == 3
        condition_1  = cases[0].case.children[0]
        assert condition_1.kind == clang.CursorKind.INTEGER_LITERAL
        assert condition_1.text == '1'
        assert cases[0].body.has_children()

        body_3 = cases[2].body.get_children()
        assert len(body_3) == 1, 'Failed to associated the children of case body to the instruction'
        assert len(body_3[0].get_children()) == 4, 'It is not correctly parsing the block of cqode defined using braces'

        body_2 = cases[1].body.get_children()
        print(body_2)
        assert len(body_2) == 3, 'Failed to associated the children of case body to the instruction'

        print('parsing switch case Test: Okay')



if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'switch_case.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
