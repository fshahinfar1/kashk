import os
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
sys.path.insert(0, root_dir)
from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from utility import find_elems_of_kind
from helpers.instruction_helper import show_insts
from data_structure import *
from instruction import *
from sym_table import *

from passes.pass_obj import PassObject
from passes.linear_code import linear_code_pass
from bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from bpf_passes.mark_user_boundary import get_number_of_failure_paths


class TestCase(BasicTest):
    def test(self, insts):
        info = self.info
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        # Generate the code and show it for debuging
        # text, _ = gen_code(bpf, self.info)
        # print(text)
        # show_insts([bpf])

        # Tests
        # NOTE: get all member references and check if the owners are correct
        # and the generated code is right.
        elems = find_elems_of_kind(bpf, clang.CursorKind.MEMBER_REF_EXPR)
        ptr = elems[-2]
        assert ptr.name == 'ptr', 'The wrong Ref object is selected for future tests'
        assert len(ptr.owner) == 2, 'The ptr should have 2 owners'
        assert ptr.owner[0].name == 'resp', 'The first owner should be the resp field'
        assert ptr.owner[1].name == 'c', 'The second owner should be the `c` pointer'
        assert ptr.owner[0].owner[0].name == ptr.owner[1].name

        e = elems[-3]
        assert e.name == 'size'
        assert len(e.owner) == 2
        assert e.owner[0].name == 'arr'
        assert e.owner[1].name == 'c'

        text, _ = gen_code([ptr], info)
        expect = 'c->resp.ptr'
        assert text == expect, f'The code generated for this member access is incorrect ({text} <=> {expect})'
        print('Parse For Loop Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/parser/')
    file_path = os.path.join(input_files_dir, 'parse_member.c')
    entry_func_name = 'event_handler'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()

