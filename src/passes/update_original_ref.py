import clang.cindex as clang
from log import debug
from instruction import *
from data_structure import *
from passes.code_pass import Pass


class UpdateOriginalRef(Pass):
    def __init__(self, info):
        super().__init__(info)
        self.target = None

    def process_current_inst(self, inst, more):
        if self.target is None:
            inst.original = inst
        else:
            inst.original = self.target
        return inst


def set_original_ref(inst, info, target):
    assert target is not None, 'in this debugging phase I do not want to set a original reference to null'
    if isinstance(inst, list):
        box = Block(BODY)
        box.children = inst
        inst = box
    UpdateOriginalRef.do(inst, info, target=target)


def update_original_ast_references(inst, info, more):
    obj = UpdateOriginalRef.do(inst, info)
    for func in Function.directory.values():
        if not func.is_used_in_bpf_code:
            continue
        tmp = UpdateOriginalRef.do(func.body, info)
