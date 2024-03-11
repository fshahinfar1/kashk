import os
import sys
from pprint import pprint

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
sys.path.insert(0, root_dir)
from basic_test_structure import BasicTest, current_file_dir

from code_gen import gen_code
from utility import find_elems_of_kind, draw_tree
from helpers.instruction_helper import show_insts
from data_structure import *
from instruction import *
from sym_table import *

from passes.pass_obj import PassObject
from passes.clone import clone_pass
from passes.simplify_code import simplify_code_structure
from passes.primary_annotation_pass import primary_annotation_pass
from passes.bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from passes.bpf_passes.mark_user_boundary import get_number_of_failure_paths
# from passes.user_passes.create_user_graph import create_user_graph
# from passes.user_passes.create_fallback import create_fallback_pass
from passes.create_failure_path import create_failure_paths
from passes.fallback_variables import failure_path_fallback_variables

from passes.mark_relevant_code import mark_relevant_code
from passes.mark_io import mark_io


def _print_node_code(node, info):
    code = node.paths.code
    # print(id(root), root.children, code)
    text, _ =  gen_code(code, info)
    print('code:\n', text, '\n---', sep='')


class TestCase(BasicTest):
    """
    Test creation of fallback handlers in the User program.
    """
    def test(self, insts):
        info = self.info
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        mark_relevant_code(bpf, info, PassObject())
        bpf = primary_annotation_pass(bpf, info, None)
        mark_io(bpf, info)
        bpf = simplify_code_structure(bpf, info, PassObject())
        bpf = feasibilty_analysis_pass(bpf, info, PassObject())

        create_failure_paths(bpf, info, None)
        failure_path_fallback_variables(info)

        all_paths = info.failure_paths
        pprint.pprint(all_paths)

        print('------- USER -------')
        text = gen_code([Function.directory['__f1'], ], info)[0]
        print(text)

        for pid, path in all_paths.items():
            print(f'# {pid}')
            text = gen_code(path, info)[0]
            print(text)
            print('~~~~~~~~~')


        print('------- BPF -------')
        text = gen_code(bpf, info)[0]
        print(text)

        assert len(info.failure_paths) == 4

        # create_fallback_pass(bpf, info, PassObject())
        # root = info.user_prog.graph
        # generated_funcs = info.user_prog.fallback_funcs_def

        # # Log
        # _print_node_code(root, self.info)
        # for x in root.children:
        #     _print_node_code(x, self.info)
        #     for c in x.children:
        #         _print_node_code(c, self.info)

        # text, _ =  gen_code(generated_funcs, info)
        # print('code:\n', text, '\n---', sep='')
        # print(generated_funcs)

        # # left_child_code = root.children[3].children[0].paths.code.children
        # # print('lll', left_child_code)


        # tree = draw_tree(info.user_prog.graph, fn=lambda x: str(id(x)))
        # print(tree)
        # # Tests
        # assert root.paths.code.has_children()
        # assert len(generated_funcs) == 2

        # root_code = root.paths.code.children
        # assert root_code[0].kind == clang.CursorKind.IF_STMT


        print('Create fallback Test: Okay')



if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/fallback/')
    # file_path = os.path.join(input_files_dir, 'feasibility_pass.c')
    file_path = os.path.join(input_files_dir, 'failure_inside_func.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
