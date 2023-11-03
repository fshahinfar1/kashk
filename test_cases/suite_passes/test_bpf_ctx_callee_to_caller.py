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
from passes.mark_used_funcs import mark_used_funcs
from passes.replace_func_ptr import replace_func_pointers
from passes.mark_io import mark_io
from passes.clone import clone_pass
from passes.linear_code import linear_code_pass

from bpf_passes.loop_end import loop_end_pass
from bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from bpf_passes.transform_vars import transform_vars_pass
from bpf_passes.userspace_fallback import userspace_fallback_pass
from bpf_passes.verifier import verifier_pass
from bpf_passes.transform_after_verifier import transform_func_after_verifier
from bpf_passes.reduce_params import reduce_params_pass

from user_passes.select_user import select_user_pass


class TestCase(BasicTest):
    def test(self, insts):
        info = self.info
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        mark_used_funcs(bpf, info, None)
        bpf = replace_func_pointers(bpf, info, None)
        mark_io(bpf, info)
        bpf = linear_code_pass(bpf, info, PassObject())
        bpf = feasibilty_analysis_pass(bpf, info, PassObject())
        select_user_pass(bpf, info, PassObject())
        bpf = loop_end_pass(bpf, info, PassObject())
        bpf = transform_vars_pass(bpf, info, PassObject())
        bpf = userspace_fallback_pass(bpf, info, PassObject())
        print(' verifier pass ------------------------------')
        bpf = verifier_pass(bpf, info, PassObject())
        print('----------------------------------------------')

        func = Function.directory['do_read']

        # Generate the code and show it for debuging
        text, _ = gen_code(bpf, info)
        print(text)

        text, _ = gen_code([func], info)
        print('Function do_read:')
        print(text)

        print('Reduce Params Pass Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/verifier/')
    file_path = os.path.join(input_files_dir, 'bpf_ctx_from_callee_to_caller.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args, 'sk_skb')
    test.run_test()
