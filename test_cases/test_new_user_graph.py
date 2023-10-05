import os
from basic_test_structure import BasicTest, current_file_dir

from bpf_code_gen import gen_code
from utility import show_insts, find_elems_of_kind, draw_tree
from data_structure import *
from instruction import *
from sym_table import *

from passes.pass_obj import PassObject
from passes.linear_code import linear_code_pass
from bpf_passes.feasibility_analysis import feasibilty_analysis_pass
from bpf_passes.mark_user_boundary import get_number_of_failure_paths
# from user_passes.select_user import select_user_pass
from user_passes.create_new_user_graph import create_new_user_graph

from cfg import make_cfg, HTMLWriter


def _print_code(code, info):
    text, _ =  gen_code(code, info)
    print('code:\n', text, '\n---', sep='')


def _print_node_code(node, info):
    code = node.paths.code
    # print(id(root), root.children, code)
    show_insts([code])
    text, _ =  gen_code(code, info)
    print('code:\n', text, '\n---', sep='')


def _tree_leafs(node):
    if len(node.children) == 0:
        return [node]
    res = []
    for c in node.children:
        l = _tree_leafs(c)
        res.extend(l)
    return res

class TestCase(BasicTest):
    def test(self, insts):
        info = self.info
        bpf = Block(BODY)
        bpf.extend_inst(insts)

        # Linear pass
        bpf = linear_code_pass(bpf, info, PassObject())
        linref = bpf
        for f in Function.directory.values():
            if not f.is_empty():
                with info.sym_tbl.with_func_scope(f.name):
                    body = linear_code_pass(f.body, info, PassObject())
                    assert body is not None
                    f.body = body

        # Feasibility pass
        bpf = feasibilty_analysis_pass(bpf, info, PassObject())

        cfg = make_cfg(bpf)
        html = HTMLWriter().cfg_to_html(cfg, info)
        with open('/tmp/test/test.html', 'w') as f:
            f.write(html)

        # Create user graph
        # select_user_pass(bpf, info, PassObject())
        create_new_user_graph(cfg, info, None)

        root = info.user_prog.graph

        # Show information
        print('\n---- Linearized Code -----')
        _print_code(linref, info)
        print('---- End of the Code ----\n')
        tree = draw_tree(info.user_prog.graph, fn=lambda x: print(gen_code(x.paths.code, info)[0]) and str(id(x)))
        print('\n---- Begining of the Tree ----')
        print(tree)
        print('---- End of the Tree ----\n')
        _print_node_code(root, info)
        for c in root.children:
            _print_node_code(c, info)
            # for x in c.children:
            #     _print_node_code(x, info)

        # Check the structure of found tree
        leafs = _tree_leafs(root)
        assert len(leafs) == 3, 'There are 3 different failure paths'
        assert len(root.children[0].children) == 0
        assert len(root.children[1].children) == 1
        # Check the selected instructions to offload

        second_path = root.children[1]
        second_path_first_inst = second_path.paths.code.children[0]
        assert second_path_first_inst.kind == clang.CursorKind.CALL_EXPR
        print(second_path_first_inst)
        assert second_path_first_inst.name == 'f2'

        print('New User Graph Test: Okay')


if __name__ == '__main__':
    input_files_dir = os.path.join(current_file_dir, './inputs/')
    file_path = os.path.join(input_files_dir, 'feasibility_pass.c')
    entry_func_name = 'main'
    compiler_args = ''
    test = TestCase(file_path, entry_func_name, compiler_args)
    test.run_test()
