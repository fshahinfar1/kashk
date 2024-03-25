import os
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
sys.path.insert(0, root_dir)
from basic_test_structure import current_file_dir
from verifier_test_structure import VerifierTest

from code_gen import gen_code
from utility import find_elems_of_kind
from helpers.instruction_helper import show_insts
from data_structure import *
from instruction import *
from sym_table import *


class TestCase(VerifierTest):
    def test(self, bpf):
        info = self.info
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
