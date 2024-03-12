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
