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
from passes.linear_code import linear_code_pass
from bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from bpf_passes.reduce_params import reduce_params_pass


class TestCase(BasicTest):
    def test(self, insts):
        info = self.info
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        mark_relevant_code(bpf, info, None)
        bpf = linear_code_pass(bpf, info, PassObject())
        bpf = reduce_params_pass(bpf, info, PassObject())

        func = Function.directory.get('func')
        func2 = Function.directory.get('func2')
        # Generate the code and show it for debuging
        # text, _ = gen_code(bpf, info)
        # print(text)

        # text, _ = gen_code([func], info)
        # print(text)

        # text, _ = gen_code([func2], info)
        # # ref_i = func2.body.children[0].body[0].rhs.children[0]
        # # print(ref_i, ref_i.kind, ref_i.owner)
        # print(text)


        type_name = func.args[-1].type_ref.spelling
        err = f'Unexpected type for last argument of func. received {type_name} expected struct __ex_func *'
        assert  type_name == 'struct __ex_func *', err
        type_name = func2.args[-1].type_ref.spelling
        err = f'Unexpected type for last argument of func2: {type_name}'
        assert type_name == 'struct __ex_func2 *', err

        ret_inst = func.body.children[0]
        ref = ret_inst.body.children[0].rhs.children[0]
        assert ref.name == 'i', 'Make sure the right reference is selected'
        assert ref.owner[0].name == '__ex', 'The references to the variables should be replaced with access to the struct'


        print('Reduce Params Pass Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'reduce_parms.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
