import clang.cindex as clang
from log import debug
from instruction import *
from data_structure import *
from passes.code_pass import Pass
from passes.clone import clone_pass

class FindUnusedVar(Pass):
    def __init__(self, info):
        super().__init__(info)

    def process_current_inst(self, inst, more):
        pass


def find_unused_vars(inst, info, target):
    """
    @param inst: body of a function (or a block of code)
    @param info:
    @param target: a list of variable names to check if they are used or not
    @returns a list of unused variable names
    """

