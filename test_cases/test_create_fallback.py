import os
from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from utility import show_insts, find_elems_of_kind, draw_tree
from data_structure import *
from instruction import *
from sym_table import *

from passes.pass_obj import PassObject
from passes.clone import clone_pass
from passes.linear_code import linear_code_pass
from bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from bpf_passes.mark_user_boundary import get_number_of_failure_paths
from user_passes.select_user import select_user_pass
from user_passes.create_fallback import create_fallback_pass


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

        # Linear pass
        bpf = linear_code_pass(bpf, info, PassObject())

        # Feasibility pass
        bpf = feasibilty_analysis_pass(bpf, info, PassObject())

        # Create user graph
        select_user_pass(bpf, info, PassObject())

        # Clone for User processing
        # user = clone_pass(bpf, info, PassObject())
        # info.user_prog.sym_tbl = info.sym_tbl.clone()
        # info.user_prog.func_dir = {}
        # for func in Function.directory.values():
        #     new_f = func.clone(info.user_prog.func_dir)

        # with info.user_prog.select_context(info):
        create_fallback_pass(bpf, info, PassObject())
        root = info.user_prog.graph
        generated_funcs = info.user_prog.fallback_funcs_def

        # Log
        _print_node_code(root, self.info)
        for x in root.children:
            _print_node_code(x, self.info)
            for c in x.children:
                _print_node_code(c, self.info)

        text, _ =  gen_code(generated_funcs, info)
        print('code:\n', text, '\n---', sep='')
        print(generated_funcs)

        left_child_code = root.children[1].children[0].paths.code.children
        print('lll', left_child_code)

        # Tests
        assert root.paths.code.has_children()
        assert len(generated_funcs) == 2

        root_code = root.paths.code.children
        assert root_code[0].kind == clang.CursorKind.IF_STMT


        print('Create fallback Test: Okay')



if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'feasibility_pass.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
