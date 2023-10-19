from log import debug
from instruction import *
from data_structure import *

from passes.pass_obj import PassObject
from passes.mark_used_funcs import mark_used_funcs
from passes.clone import clone_pass


MODULE_TAG = '[Replace Func Ptr]'
exclude_inst_flag = False
skip_path_flag = False
func_ptr_mapping = {}


def _set_exclude_flag(val):
    global exclude_inst_flag
    exclude_inst_flag = val


def _set_skip_path(val):
    global skip_path_flag
    skip_path_flag = val


def _process_current_inst(inst, info):
    if inst.kind == ANNOTATION_INST:
        if inst.ann_kind == Annotation.ANN_FUNC_PTR:
            ptr, actual = inst.msg.split(Annotation.FUNC_PTR_DELIMITER)
            func_ptr_mapping[ptr] = actual
            # debug(MODULE_TAG, ptr, '-->', actual)
            return None
        elif inst.ann_kind == Annotation.ANN_EXCLUDE_BEGIN:
            _set_exclude_flag(True)
            return None
        elif inst.ann_kind == Annotation.ANN_EXCLUDE_END:
            _set_exclude_flag(False)
            return None
        # elif inst.ann_kind == Annotation.ANN_SKIP:
        #     _set_skip_path(True)
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        if inst.is_func_ptr:
            actual = func_ptr_mapping.get(inst.name)
            if actual is not None:
                # bind function pointer to an actual function
                report(MODULE_TAG, f'Function {inst.name} is replaced with {actual}')
                new_inst = clone_pass(inst, info, PassObject())
                new_inst.name = actual
                new_inst.is_func_ptr = False

                func = new_inst.get_function_def()
                assert func is not None, f'Function {new_inst.name} was not found'
                if not func.is_used_in_bpf_code:
                    # This function has just got accessibile
                    assert func is not None
                    func.is_used_in_bpf_code = True
                    info.prog.declarations.insert(0, func)

                    # NOTE: I am not putting this pass before
                    # mark_used_funcs pass because I do not want to analyse
                    # all the functions.
                    mark_used_funcs(func.body, info, None)
                return new_inst
    return inst


def _do_pass(inst, info):
    inst = _process_current_inst(inst, info)
    if inst is None:
        return inst
    new_children = []
    for child, tag in inst.get_children_context_marked():
        if isinstance(child, list):
            new_child = []
            for i in child:
                new_inst = _do_pass(i, info)
                if exclude_inst_flag:
                    continue
                if new_inst is not None:
                    new_child.append(new_inst)
        else:
            new_child = _do_pass(child, info)
        new_children.append(new_child)
    new_inst = inst.clone(new_children)
    return new_inst


def replace_func_pointers(bpf, info, more):
    """
    Apply some of the annotations
    1. Function pointer
    2. Exclude regions
    """
    global func_ptr_mapping
    func_ptr_mapping = {}
    res = _do_pass(bpf, info)
    for func in Function.directory.values():
        if func.is_used_in_bpf_code:
            func.body = _do_pass(func.body, info)
    return res
