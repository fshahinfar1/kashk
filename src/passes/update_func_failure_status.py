import clang.cindex as clang
from log import debug
from instruction import *
from data_structure import *
from passes.code_pass import Pass


# TODO: we need to also check if the function may succeed again (I guess not
# neccessary with the current transformations but in general would be good)


class UpdateFuncFailureStatus(Pass):
    def process_current_inst(self, inst, more):
        if inst.kind == clang.CursorKind.CALL_EXPR:
            func = inst.get_function_def()
            if func is None or func.is_empty():
                return inst
            UpdateFuncFailureStatus.do(func.body, self.info, func=func)
            if func.may_fail and self.current_function is not None:
                self.current_function.may_fail = True
        elif inst.kind == TO_USERSPACE_INST:
            if self.current_function is not None:
                self.current_function.may_fail = True

        return inst


def update_function_failure_status(inst, info, more):
    UpdateFuncFailureStatus.do(inst, info, more)
