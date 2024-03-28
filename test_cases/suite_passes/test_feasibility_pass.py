import os
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
sys.path.insert(0, root_dir)
from basic_test_structure import BasicTest, current_file_dir

from code_gen import gen_code
from utility import find_elems_of_kind
from helpers.instruction_helper import show_insts
from data_structure import *
from instruction import *
from sym_table import *

from passes.pass_obj import PassObject
from passes.mark_relevant_code import mark_relevant_code
from passes.simplify_code import simplify_code_structure
from passes.create_failure_path import create_failure_paths
from passes.bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from passes.update_original_ref import update_original_ast_references


class TestCase(BasicTest):
    def test(self, insts):
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        mark_relevant_code(bpf, self.info, None)

        update_original_ast_references(bpf, self.info, None)
        # Store the original version of the source code (unchanged) for future use
        tmp_fn_dir = {}
        for k, f in Function.directory.items():
            f.clone(tmp_fn_dir)
        tmp_f = Function('[[main]]', None, tmp_fn_dir)
        tmp_f.body = bpf
        self.info.original_ast = tmp_fn_dir

        bpf = simplify_code_structure(bpf, self.info, PassObject())
        bpf = feasibilty_analysis_pass(bpf, self.info, PassObject())
        create_failure_paths(bpf, self.info, None)

        # Generate the code and show it for debuging
        # text, _ = gen_code(bpf, self.info)
        # print(text)
        # show_insts([bpf])

        f4 = Function.directory['f4']

        expected_state = {
                #      Succeed, Fail
                'f1': (True, False),
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

        failure_paths = len(self.info.failure_paths)
        count_expected_failures = 5
        assert  failure_paths == count_expected_failures, f'Expect {count_expected_failures} failure paths found {failure_paths}'
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
