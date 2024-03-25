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
        text = gen_code(bpf, self.info)[0]
        print(text)


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/verifier/')
    file_path = os.path.join(input_files_dir, 'fallback_from_bound_check.c')
    entry_func_name = 'main'
    compiler_args = ''
    hook = 'sk_skb'
    test = TestCase(file_path, entry_func_name, compiler_args, hook)
    test.run_test()
