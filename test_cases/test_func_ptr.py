import os
from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from utility import show_insts, find_elems_of_kind
from data_structure import *
from instruction import *
from sym_table import *


class TestCase(BasicTest):
    def test(self, insts):
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        # Generate the code and show it for debuging
        # text, _ = gen_code(bpf, self.info)
        # print(text)
        # show_insts(insts)
        # print(self.info.prog.connection_state)

        assert len(self.info.prog.connection_state) == 0, 'There is no per connection shared state'

        refs = find_elems_of_kind(insts, clang.CursorKind.DECL_REF_EXPR)

        ref = refs[0]
        assert ref.name == 'mul', 'Make sure the right reference is selected in test case'
        assert ref.is_func_ptr() == True, 'The reference was not recognized as function pointer'

        funcs = find_elems_of_kind(insts, clang.CursorKind.CALL_EXPR)
        assert len(funcs)== 1, 'Three is only one function call in the code'

        fnptr = funcs[0]
        assert len(fnptr.args) == 2, 'The function should have two arguments'
        assert fnptr.is_method == False, 'The function invokation is not a method'
        assert len(fnptr.owner) > 0, 'The call expression is not recognized as function ptr'
        assert fnptr.owner[-1].name == 'r', 'The owner of the function pointer should be variable `r`'


        # assert fnptr
        print('Function Pointer Test: Okay')



if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'func_ptr.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
