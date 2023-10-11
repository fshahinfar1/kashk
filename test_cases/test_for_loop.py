import os
from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from utility import show_insts, find_elems_of_kind
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
        text, _ = gen_code(bpf, self.info)
        print(text)
        # show_insts([bpf])

        # Tests


        print('Parse For Loop Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'parse_for.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()

