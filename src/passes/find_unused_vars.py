import clang.cindex as clang
from log import debug
from instruction import *
from data_structure import *
from passes.code_pass import Pass


class FindUnusedVar(Pass):
    def __init__(self, info):
        super().__init__(info)
        self.target = set()

    def process_current_inst(self, inst, more):
        match inst.kind:
            case clang.CursorKind.DECL_REF_EXPR:
                if inst.name in self.target:
                    self.target.remove(inst.name)
            case clang.CursorKind.MEMBER_REF_EXPR:
                assert len(inst.owner) == 1
                owner = inst.owner[-1]
                self.process_current_inst(owner, more)
        return inst


def find_unused_vars(inst, info, target):
    """
    @param inst: body of a function (or a block of code)
    @param info:
    @param target: a list/set of variable names to check if they are used or not
    @returns a set of unused variable names
    """
    if not isinstance(target, set):
        target = set(target)
    obj = FindUnusedVar.do(inst, info, target=target)
    return obj.target
