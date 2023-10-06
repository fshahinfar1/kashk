import os
from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from utility import show_insts, find_elems_of_kind
from data_structure import *
from instruction import *
from sym_table import *

from passes.pass_obj import PassObject
from passes.linear_code import linear_code_pass
from bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from bpf_passes.reduce_params import reduce_params_pass


class TestCase(BasicTest):
    def test(self, insts):
        info = self.info
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        bpf = linear_code_pass(bpf, info, PassObject())
        bpf = reduce_params_pass(bpf, info, PassObject())

        # Generate the code and show it for debuging
        text, _ = gen_code(bpf, info)
        print(text)

        func = Function.directory.get('func')
        text, _ = gen_code([func], info)
        print(text)

        func2 = Function.directory.get('func2')
        # text, _ = gen_code([func2], info)
        # print(text)


        assert func.args[-1].type == 'struct __ex_func *'
        assert func2.args[-1].type == 'struct __ex_func2 *'

        ret_inst = func.body.children[0]
        assert ret_inst.body[0].rhs.children[0].name != 'i', 'The references to the variables should be replaced with access to the struct'


        print('Reduce Params Pass Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'reduce_parms.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
