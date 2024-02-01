from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *
from user import FallbackRegionGraph

from cfg import CFGNode, CFGJump
from helpers.cfg_graphviz import CFGGraphviz
from brain.basic_block import create_basic_block_cfg
from brain.exec_path import extract_exec_paths


MODULE_TAG = '[Select Userspace]'


def _insts_in(path):
    for block in path.blocks:
        if isinstance(block, CFGNode):
            insts = block.insts
        elif isinstance(block, CFGJump):
            insts = [block.cond,]
        else:
            raise Exception('Unexpected CFG node')
        for inst in insts:
            yield inst


class CreateUserGraph:
    @classmethod
    def do(cls, inst, info):
        obj = CreateUserGraph(info)
        res = obj._analyse_func_body(inst)
        obj.result = res
        return obj

    def __init__(self, info):
        self.info = info

    def _process_path(self, path):
        root = cur_node = FallbackRegionGraph()
        failed = False
        to_user_ref = None
        gathered_insts = []
        for inst in _insts_in(path):
            if failed:
                gathered_insts.append(inst)
                continue
            if inst.kind == TO_USERSPACE_INST:
                to_user_ref = inst
                failed = True
            elif inst.kind == clang.CursorKind.CALL_EXPR:
                func = inst.get_function_def()
                if not func.may_fail:
                    continue
                with self.info.sym_tbl.with_func_scope(func.name):
                    tmp = CreateUserGraph.do(func.body, self.info)
                    func_root = tmp.result
                    # debug('@', inst.name, tag=MODULE_TAG)
                    # debug(func.may_fail, func.may_succeed, tag=MODULE_TAG)
                    # debug(func_root, func_root.children, tag=MODULE_TAG)
                    assert not func_root.is_empty(), 'The function may fail, there should be a failure path!'
                    assert not func_root.paths.code.has_children(), 'The root of the failure graph should not have any code associated with it'
                    cur_node.add_child(func_root)
        # End of a path
        if not failed:
            return root
        debug('end of failure path', tag=MODULE_TAG)
        assert to_user_ref is not None, 'End of userland region without a reference to the ToUserspace instruction.'
        user_inst = Block(BODY)
        user_inst.children = gathered_insts
        path = cur_node.paths
        path.code = user_inst
        path.original_scope = self.info.sym_tbl.current_scope
        path.to_user_inst = to_user_ref
        cur_node.set_id(to_user_ref.path_id)
        return root

    def _analyse_func_body(self, inst):
        root = FallbackRegionGraph()
        cfg = create_basic_block_cfg(inst, self.info)
        exec_paths = extract_exec_paths(cfg, self.info)
        for path in exec_paths:
            sub_graph = self._process_path(path)
            if sub_graph.is_empty():
                continue
            root.add_child(sub_graph)
        return root


def create_user_graph(inst, info, more):
    obj = CreateUserGraph.do(inst, info)
    root = obj.result
    info.user_prog.graph = root
