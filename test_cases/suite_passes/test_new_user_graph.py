import os
import sys

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
sys.path.insert(0, root_dir)
from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from utility import find_elems_of_kind, draw_tree
from helpers.instruction_helper import show_insts
from data_structure import *
from instruction import *
from sym_table import *

from passes.pass_obj import PassObject
from passes.linear_code import linear_code_pass
from bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from bpf_passes.mark_user_boundary import get_number_of_failure_paths
from user_passes.select_user import select_user_pass


def _print_node_code(node, info):
    code = node.paths.code
    # print(id(root), root.children, code)
    text, _ =  gen_code(code, info)
    print('code:\n', text, '\n---', sep='')


class TestCase(BasicTest):
    def test(self, insts):
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        # Linear pass
        bpf = linear_code_pass(bpf, self.info, PassObject())
        for f in Function.directory.values():
            if not f.is_empty():
                with self.info.sym_tbl.with_func_scope(f.name):
                    body = linear_code_pass(f.body, self.info, PassObject())
                    assert body is not None
                    f.body = body

        # Feasibility pass
        bpf = feasibilty_analysis_pass(bpf, self.info, PassObject())

        # Create user graph
        select_user_pass(bpf, self.info, PassObject())

        root = self.info.user_prog.graph

        # # Show information
        tree = draw_tree(self.info.user_prog.graph, fn=lambda x: str(id(x)))
        print('\n---- Begining of the Tree ----')
        # print(tree)
        # print('---- End of the Tree ----\n')
        # _print_node_code(root, self.info)
        # for c in root.children:
        #     _print_node_code(c, self.info)
        #     for x in c.children:
        #         _print_node_code(x, self.info)

        # Check the structure of found tree
        assert len(root.children) == 2
        assert len(root.children[0].children) == 0
        assert len(root.children[1].children) == 2
        # Check the selected instructions to offload

        second_path = root.children[1]
        second_path_first_inst = second_path.paths.code.children[0]
        assert second_path_first_inst.kind == clang.CursorKind.CALL_EXPR
        assert second_path_first_inst.name == 'f2'

        print('New User Graph Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'feasibility_pass.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
