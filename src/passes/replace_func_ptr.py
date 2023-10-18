from dfs import DFSPass
from instruction import *
from data_structure import *

from passes.mark_used_funcs import mark_used_funcs


MODULE_TAG = '[Replace Func Ptr]'


def _do_pass(bpf, info):
    func_ptr_mapping = {}
    d = DFSPass(bpf)
    for inst, lvl in d:
        if inst.kind == ANNOTATION_INST:
            if inst.ann_kind == Annotation.ANN_FUNC_PTR:
                ptr, actual = inst.msg.split(Annotation.FUNC_PTR_DELIMITER)
                func_ptr_mapping[ptr] = actual
        elif inst.kind == clang.CursorKind.CALL_EXPR:
            if inst.is_func_ptr:
                actual = func_ptr_mapping.get(inst.name)
                if actual is not None:
                    # bind function pointer to an actual function
                    report(MODULE_TAG, f'Function {inst.name} is replaced with {actual}')
                    inst.name = actual
                    inst.is_func_ptr = False

                    func = inst.get_function_def()
                    if not func.is_used_in_bpf_code:
                        # This function has just got accessibile
                        assert func is not None
                        func.is_used_in_bpf_code = True
                        info.prog.declarations.insert(0, func)

                        # NOTE: I am not putting this pass before
                        # mark_used_funcs pass because I do not want to analyse
                        # all the functions.
                        mark_used_funcs(func.body, info, None)
        d.go_deep()


def replace_func_pointers(bpf, info, more):
    _do_pass(bpf, info)
