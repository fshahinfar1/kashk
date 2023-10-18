import os
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
sys.path.insert(0, root_dir)
from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from utility import show_insts, find_elems_of_kind
from data_structure import *
from instruction import *
from sym_table import *

from passes.pass_obj import PassObject
from passes.mark_used_funcs import mark_used_funcs
from passes.linear_code import linear_code_pass
from bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from bpf_passes.mark_user_boundary import get_number_of_failure_paths


class TestCase(BasicTest):
    def test(self, insts):
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        mark_used_funcs(bpf, self.info, None)
        bpf = linear_code_pass(bpf, self.info, PassObject())
        for f in Function.directory.values():
            if not f.is_empty():
                with self.info.sym_tbl.with_func_scope(f.name):
                    body = linear_code_pass(f.body, self.info, PassObject())
                    assert body is not None
                    f.body = body

        bpf = feasibilty_analysis_pass(bpf, self.info, PassObject())

        # Generate the code and show it for debuging
        # text, _ = gen_code(bpf, self.info)
        # print(text)

        # show_insts([bpf])

        expected_state = {
                #      Succeed, Fail
                'f1': (False, True),
                'f2': (False, True),
                'f3': (True, False),
                # 'main': (True, True),
                'calloc': (False, True),
                'pthread_mutex_init': (False, True),
                'pthread_mutex_lock': (False, True),
                'pthread_mutex_unlock': (False, True),
                }
        for func in sorted(Function.directory.values(), key=lambda x: x.name):
            key = func.name
            if key not in expected_state:
                continue
            assert (func.may_succeed, func.may_fail) == expected_state[func.name], f'For funct {func.name} the expectation does not match (s:{func.may_succeed}, f:{func.may_fail})'

        failure_paths = get_number_of_failure_paths()
        assert  failure_paths == 3, f'Expect 3 failure paths found {failure_paths}'
        # Find the first breaking point
        ifs = find_elems_of_kind(bpf, clang.CursorKind.IF_STMT)
        first_if = ifs[0]
        first_if_first_inst = first_if.body.children[0]
        assert first_if_first_inst.kind == TO_USERSPACE_INST

        # Check the second breaking point
        f2 = Function.directory['f2']
        second_inst = f2.body.children[1]
        assert second_inst.kind == TO_USERSPACE_INST

        print('Feasibility Pass Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'feasibility_pass.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
