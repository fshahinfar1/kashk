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



class TestCase(BasicTest):
    def test(self, insts):
        info = self.info
        prog = Block(BODY)
        prog.extend_inst(insts)

        # BPF_MAIN = 'BPF_MAIN_SCOPE'
        # print(info.sym_tbl.scope_mapping[BPF_MAIN].symbols)

        mark_relevant_code(prog, info, None)
        prog = primary_annotation_pass(prog, info, None)
        mark_io(prog, info)
        prog = simplify_code_structure(prog, info, PassObject())
        prog = feasibilty_analysis_pass(prog, info, PassObject())
        create_user_graph(prog, info, PassObject())
        prog = loop_end_pass(prog, info, PassObject())
        prog = transform_vars_pass(prog, info, PassObject())
        prog = userspace_fallback_pass(prog, info, PassObject())
        print(' verifier pass ------------------------------')
        prog = verifier_pass(prog, info, PassObject())
        print('----------------------------------------------')

        # Generate the code and show it for debuging
        process_func = Function.directory['process']

        text, _ = gen_code([process_func,], info)
        print(text)

        text, _ = gen_code(prog, info)
        print(text)

        # Tests
        elems = find_elems_of_kind(process_func.body, clang.CursorKind.IF_STMT)
        assert len(elems) > 0, 'The compiler should add bound check to process function'

        elems = find_elems_of_kind(prog, clang.CursorKind.IF_STMT)
        assert len(elems) > 0, 'The compiler should add an if statment'

        print('Reduce Params Pass Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/verifier/')
    file_path = os.path.join(input_files_dir, 'func_call.c')
    entry_func_name = 'main'
    compiler_args = ''

    #  'sk_skb'
    for hook in ('xdp',):
        print('Hook:', hook)
        test = TestCase(file_path, entry_func_name, compiler_args, hook)
        test.run_test()
        print('--------------------------------------------')
