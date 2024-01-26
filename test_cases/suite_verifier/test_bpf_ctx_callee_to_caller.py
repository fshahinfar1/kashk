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
from passes.mark_relevant_code import mark_relevant_code
from passes.primary_annotation_pass import primary_annotation_pass
from passes.mark_io import mark_io
from passes.clone import clone_pass
from passes.simplify_code import simplify_code_structure

from passes.bpf_passes.loop_end import loop_end_pass
from passes.bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from passes.bpf_passes.transform_vars import transform_vars_pass
from passes.bpf_passes.userspace_fallback import userspace_fallback_pass
from passes.bpf_passes.verifier import verifier_pass
from passes.bpf_passes.transform_after_verifier import transform_func_after_verifier
from passes.bpf_passes.reduce_params import reduce_params_pass

from passes.user_passes.select_user import select_user_pass


class TestCase(BasicTest):
    def test(self, insts):
        info = self.info
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        mark_relevant_code(bpf, info, None)
        bpf = primary_annotation_pass(bpf, info, None)
        mark_io(bpf, info)
        bpf = simplify_code_structure(bpf, info, PassObject())
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

        for i in range(1, 6):
            var_name = f'req{i}'
            sym = self.info.sym_tbl.lookup(var_name)
            assert sym is not None, f'Did not found the symbol for the variable {var_name}'
            assert sym.is_bpf_ctx, f'The variable was not recognized as pointer to BPF ctx'

        print('Tracking BPF context from callee to caller: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/verifier/')
    file_path = os.path.join(input_files_dir, 'bpf_ctx_from_callee_to_caller.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args, 'sk_skb')
    test.run_test()
