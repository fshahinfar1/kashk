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

from helpers.instruction_helper import show_insts


MODULE_TAG = '[Create User Graph]'


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
        self._init()

    def _init(self):
        self.root = self.cur_node = FallbackRegionGraph()
        self.failed = False
        self.to_user_ref = None
        self.gathered_insts = []

    def _process_inst(self, inst):
        if inst.kind == TO_USERSPACE_INST:
            debug('failed @', inst, tag=MODULE_TAG)
            self.to_user_ref = inst
            self.failed = True
        elif inst.kind == clang.CursorKind.CALL_EXPR:
            func = inst.get_function_def()
            if not func.may_fail:
                return
            with self.info.sym_tbl.with_func_scope(func.name):
                tmp = CreateUserGraph.do(func.body, self.info)
                func_root = tmp.result
                debug('@', inst.name, tag=MODULE_TAG)
                debug(func.may_fail, func.may_succeed, tag=MODULE_TAG)
                debug(func_root, func_root.children, tag=MODULE_TAG)
                debug(func_root.paths.code.children)
                # show_insts(func_root.paths.code)
                # if func_root.is_empty:
                #     tmp = Literal('/*This failure path did not had any instructions */', CODE_LITERAL)
                #     func_root.paths.code.add_inst(tmp)
                assert not func_root.is_empty(), 'The function may fail, there should be a failure path!'
                # assert not func_root.paths.code.has_children(), 'The self.root of the failure graph should not have any code associated with it'
                self.cur_node.add_child(func_root)

    def _process_path(self, path):
        self._init()
        for inst in _insts_in(path):
            if self.failed:
                self.gathered_insts.append(inst)
                continue
            self._process_inst(inst)
        # End of a path
        if not self.failed:
            return self.root
        debug('end of failure path', tag=MODULE_TAG)
        assert self.to_user_ref is not None, 'End of userland region without a reference to the ToUserspace instruction.'
        user_inst = Block(BODY)
        user_inst.children = self.gathered_insts
        path = self.cur_node.paths
        path.code = user_inst
        path.original_scope = self.info.sym_tbl.current_scope
        path.to_user_inst = self.to_user_ref
        self.cur_node.set_id(self.to_user_ref.path_id)
        return self.root

    def _analyse_func_body(self, inst):
        self.root = FallbackRegionGraph()
        cfg = create_basic_block_cfg(inst, self.info)

        tmp = CFGGraphviz.do(cfg, self.info)
        tmp.dot.save('/tmp/cfg.dot')
        tmp.dot.render(filename='cfg', directory='/tmp/', format='svg')

        exec_paths = extract_exec_paths(cfg, self.info)
        debug('len exec paths:', len(exec_paths))
        for path in exec_paths:
            sub_graph = self._process_path(path)
            if sub_graph.is_empty():
                continue
            self.root.add_child(sub_graph)
        return self.root


def create_user_graph(inst, info, more):
    obj = CreateUserGraph.do(inst, info)
    root = obj.result
    info.user_prog.graph = root
