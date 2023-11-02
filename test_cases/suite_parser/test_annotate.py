import os
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
sys.path.insert(0, root_dir)

from basic_test_structure import BasicTest, current_file_dir

from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from data_structure import *
from instruction import *
from sym_table import *
from helpers.instruction_helper import show_insts


class TestCase(BasicTest):
    def test(self, insts):
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        show_insts(bpf)

        ann = bpf.children[0]
        print(ann.msg)
        assert ann.kind == ANNOTATION_INST
        assert ann.msg == 'hello'
        assert ann.ann_kind == Annotation.ANN_SKIP
        print('Parsing Annotation Test: Okay')



if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'annotation.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
