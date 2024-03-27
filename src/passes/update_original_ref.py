import clang.cindex as clang
from log import debug
from instruction import *
from data_structure import *
from passes.code_pass import Pass


class UpdateOriginalRef(Pass):
    def __init__(self, info):
        super().__init__(info)
        # None means that each instruction will point to itself
        self.target = None

    def _update_owner(self, inst):
        target = self.target if self.target is not None else inst
        list_owner = inst.owner
        while list_owner:
            more = []
            for o in list_owner:
                o.original = target
                if o.kind == clang.CursorKind.MEMBER_REF_EXPR:
                    # Also investigate the parents of the parent
                    more += o.owner
            list_owner = more

    def process_current_inst(self, inst, more):
        if self.target is None:
            inst.original = inst
        else:
            inst.original = self.target

        # NOTE: A hack: since the owners of a references are not traversed, I
        # am doing it manually here.
        if inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
            self._update_owner(inst)
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
