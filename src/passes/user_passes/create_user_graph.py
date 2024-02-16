from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *
from code_pass import Pass
from user import FallbackRegionGraph


MODULE_TAG = '[Create User Graph]'


class CreateUserGraph(Pass):
    @classmethod
    def do(cls, inst, info, *args, **kwargs):
        obj = super().do(inst, info, *args, **kwargs)
        if obj.gathered_insts is not None:
            obj._end_of_failure_path()
        return obj

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.node_ref = CodeBlockRef()

        self.failed = False
        self.gathered_insts = None
        self.root = FallbackRegionGraph()
        self.cur_node_stack = [(self.root, None), ]

    @property
    def cur_node(self):
        return self.cur_node_stack[-1][0]

    def _end_of_failure_path(self):
        debug('end of failure path', tag=MODULE_TAG)
        node, to_user_inst_ref = self.cur_node_stack[-1]
        assert to_user_inst_ref is not None, 'End of userland region without a reference to the ToUserspace instruction.'
        user_inst = Block(BODY)
        user_inst.children = self.gathered_insts
        path = node.append(user_inst)
        path.original_scope = self.info.sym_tbl.current_scope
        path.to_user_inst = to_user_inst_ref
        node.set_id(to_user_inst_ref.path_id)
        self.cur_node_stack.pop()

    def process_current_inst(self, inst, more):
        if inst.kind == TO_USERSPACE_INST:
            # Entering the userland
            assert self.failed is False, 'Overlapping TO_USERSPACE_INST was not expected'
            self.failed = True
            self.gathered_insts = []
            new_node = self.cur_node.new_child()
            tmp = (new_node, inst)
            self.cur_node_stack.append(tmp)
            return inst

        if self.failed:
            self.gathered_insts.append(inst)
            self.skip_children()
            return inst

        # If we have not failed, and we are calling a function which might fail
        if inst.kind == clang.CursorKind.CALL_EXPR:
            func = inst.get_function_def()
            if not func.may_fail:
                return inst
            with self.set_current_func(func):
                tmp_res = CreateUserGraph.do(func.body, self.info)
                func_root = tmp_res.root
                # debug('@', inst.name, tag=MODULE_TAG)
                # debug(func.may_fail, func.may_succeed, tag=MODULE_TAG)
                # debug(func_root, func_root.children, tag=MODULE_TAG)
                assert not func_root.is_empty(), 'The function may fail, there should be a failure path!'
                assert not func_root.paths.code.has_children(), 'The root of the failure graph should not have any code associated with it'
                for child in func_root.children:
                    self.cur_node.add_child(child)

        return inst


def create_user_graph(inst, info, more):
    obj = CreateUserGraph.do(inst, info, more)
    root = obj.root
    info.user_prog.graph = root
