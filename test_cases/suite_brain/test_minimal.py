import os
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
sys.path.insert(0, root_dir)
from brain_test_structure import BrainTest

from data_structure import *
from instruction import *
from sym_table import *
from code_gen import gen_code
from utility import find_elems_of_kind
from helpers.instruction_helper import show_insts

from brain.cost_func import context_switch
from cfg import cfg_leafs


class TestCase(BrainTest):
    def test(self, prog):
        info = self.info
        # Generate the code and show it for debuging
        # text, _ = gen_code(prog, info)
        # print(text)
        cfg = self.main_cfg
        # self.show_cfg(cfg)

        leafs = cfg_leafs(cfg)
        assert len(leafs) == 1
        assert leafs[0].expected_cost == -1 * context_switch
        assert self.info.user_prog.graph.is_empty(), 'every thing is offload to bpf'


if __name__ == '__main__':
    input_files_dir = os.path.join(curdir, '../inputs/brain/')
    # input_files_dir = os.path.abspath(input_files_dir)
    print(input_files_dir)
    file_path = os.path.join(input_files_dir, 'minimal.c')
    entry_func_name = 'main'
    compiler_args = ''
    hook = 'sk_skb'
    test = TestCase(file_path, entry_func_name, compiler_args, hook)
    test.run_test()
