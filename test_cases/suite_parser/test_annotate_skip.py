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

from passes.mark_relevant_code import mark_relevant_code
from passes.pass_obj import PassObject
from passes.simplify_code import simplify_code_structure
from passes.bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from passes.create_failure_path import create_failure_paths


class TestCase(BasicTest):
    def test(self, insts):
        info = self.info
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        mark_relevant_code(bpf, info, None)

        bpf = simplify_code_structure(bpf, info, PassObject())
        for f in Function.directory.values():
            if not f.is_empty():
                with self.info.sym_tbl.with_func_scope(f.name):
                    body = simplify_code_structure(f.body, self.info, PassObject())
                    assert body is not None
                    f.body = body

        bpf = feasibilty_analysis_pass(bpf, self.info, PassObject())
        create_failure_paths(bpf, self.info, None)

        # Generate the code and show it for debuging
        # text, _ = gen_code(bpf, self.info)
        # print(text)
        # show_insts([bpf])

        # Tests
        failure_paths = len(info.failure_paths)
        assert  failure_paths == 4, f'Expect 4 failure paths found {failure_paths}'

        print('Feasibility Pass Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'annotate_skip.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
