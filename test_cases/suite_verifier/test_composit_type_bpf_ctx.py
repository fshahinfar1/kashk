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

from passes.user_passes.create_user_graph import create_user_graph


class TestCase(BasicTest):
    def test(self, insts):
        info = self.info
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        # BPF_MAIN = 'BPF_MAIN_SCOPE'
        # print(info.sym_tbl.scope_mapping[BPF_MAIN].symbols)

        mark_relevant_code(bpf, info, None)
        bpf = primary_annotation_pass(bpf, info, None)
        mark_io(bpf, info)
        bpf = simplify_code_structure(bpf, info, PassObject())
        bpf = feasibilty_analysis_pass(bpf, info, PassObject())
        create_user_graph(bpf, info, PassObject())
        bpf = loop_end_pass(bpf, info, PassObject())
        bpf = transform_vars_pass(bpf, info, PassObject())
        bpf = userspace_fallback_pass(bpf, info, PassObject())
        print(' verifier pass ------------------------------')
        bpf = verifier_pass(bpf, info, PassObject())
        print('----------------------------------------------')

        func = Function.directory['access_data']

        # Generate the code and show it for debuging
        text, _ = gen_code(bpf, info)
        print(text)

        text, _ = gen_code([func,], info)
        print(text)


        # Tests
        elems = find_elems_of_kind(func.body, clang.CursorKind.IF_STMT)
        assert len(elems) > 0, 'The compiler should add an if statment'

        print('Reduce Params Pass Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/verifier/')
    file_path = os.path.join(input_files_dir, 'composit_type_bpf_ctx.c')
    entry_func_name = 'process_event'
    compiler_args = ''

    #  'sk_skb'
    for hook in ('xdp',):
        print('Hook:', hook)
        test = TestCase(file_path, entry_func_name, compiler_args, hook)
        test.run_test()
        print('--------------------------------------------')
