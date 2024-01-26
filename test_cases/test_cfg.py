import os
from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from helpers.instruction_helper import show_insts
from data_structure import *
from instruction import *
from sym_table import *

from passes.simplify_code import simplify_code_structure
from passes.pass_obj import PassObject

from cfg import make_cfg, HTMLWriter


class TestCase(BasicTest):
    def test(self, insts):
        info = self.info
        # Get ready for a pass
        bpf = Block(BODY)
        bpf.extend_inst(insts)
        # Move function calls out of the ARG context!
        bpf = simplify_code_structure(bpf, self.info, PassObject())

        # Generate the code and show it for debuging
        # text, _ = gen_code(bpf, self.info)
        # print(text)

        root = make_cfg(bpf)
        writer = HTMLWriter()
        text = writer.cfg_to_html(root, info)
        # with open('/tmp/test/index.html', 'w') as f:
        #     f.write(text)
        print (text)
        print('CFG Test: Okay')



if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'cfg.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()

