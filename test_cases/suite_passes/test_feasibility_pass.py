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
from bpf_passes.mark_user_boundary import get_number_of_failure_paths


class TestCase(BasicTest):
    def test(self, insts):
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        mark_relevant_code(bpf, self.info, None)
        bpf = linear_code_pass(bpf, self.info, PassObject())
        bpf = feasibilty_analysis_pass(bpf, self.info, PassObject())

        # Generate the code and show it for debuging
        # text, _ = gen_code(bpf, self.info)
        # print(text)
        # show_insts([bpf])

        f4 = Function.directory['f4']
        # text, _ = gen_code([f4, ], self.info)
        # print(text)

        expected_state = {
                #      Succeed, Fail
                'f1': (False, True),
                'f2': (False, True),
                'f3': (True, False),
                'f4': (True, True),
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
        assert  failure_paths == 4, f'Expect 4 failure paths found {failure_paths}'
        # Find the first failure point
        ifs = find_elems_of_kind(bpf, clang.CursorKind.IF_STMT)
        first_if = ifs[0]
        first_if_first_inst = first_if.body.children[0]
        assert first_if_first_inst.kind == TO_USERSPACE_INST

        # NOTE: previously we would fallback exactly on the isntruction that
        # failed. At somepoint I change the logic to fallback before calling a
        # function that may never succeed. I am not sure which approach is
        # better.
        # # Check the second breaking point
        # f2 = Function.directory['f2']
        # second_inst = f2.body.children[1]
        # assert second_inst.kind == TO_USERSPACE_INST

        inst = ifs[1].body.children[1]
        assert inst.kind == TO_USERSPACE_INST
        inst = ifs[2].body.children[0]
        assert inst.kind == TO_USERSPACE_INST

        ifs = find_elems_of_kind(f4.body, clang.CursorKind.IF_STMT)
        assert len(ifs) == 1
        assert ifs[0].body.children[0].kind == TO_USERSPACE_INST

        print('Feasibility Pass Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'feasibility_pass.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
