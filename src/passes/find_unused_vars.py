import clang.cindex as clang
from log import debug
from instruction import *
from data_structure import *
from passes.code_pass import Pass
from passes.clone import clone_pass
from helpers.instruction_helper import show_insts


MODULE_TAG = '[Remove Unused Args]'


def remove_indicies_from_arr(arr, indicies):
    # NOTE: indicies must be sorted
    orig_count = len(arr)
    new_count = (orig_count - len(indicies))
    # debug('---', new_count, orig_count, len(indicies), tag=MODULE_TAG)
    # debug(indicies, tag=MODULE_TAG)

    assert all([i < orig_count for i in indicies]), 'index out of range of function arguments'
    assert new_count >= 0
    new = [None] * new_count
    j = 0 # index on the old arr
    k = 0 # index on the new arr
    # Adding the length of the array to the list to make sure the for loop
    # will not terminate until the end
    for skip in indicies + [orig_count,]:
        while j < orig_count:
            if j == skip:
                # skip this, go see what is the next index to skip
                j += 1
                break
            item = arr[j]
            new[k] = item
            k += 1
            j += 1
    assert all(x is not None for x in new), str(new)
    return new


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


class CheckForFuncCall(Pass):
    """
    Find function calls inside a body of code and remove arguments indicated by
    a list of indices in `rm_func` map.
    """
    def __init__(self, info):
        super().__init__(info)
        self.rm_func = None

    def process_current_inst(self, inst, more):
        if inst.kind != clang.CursorKind.CALL_EXPR:
            return inst
        if inst.name not in self.rm_func:
            return inst

        f = inst.get_function_def()
        assert len(inst.args) == len(f.args), f.name

        new_inst = clone_pass(inst)
        # NOTE: indicies must be sorted
        indicies = self.rm_func[inst.name]

        new_args = remove_indicies_from_arr(new_inst.args, indicies)
        new_inst.args = new_args
        return new_inst


def _do_remove_unused_args(inst, info, more):
    rm_func = {}
    # TODO: may be do this on all the function instead of just the failure
    # functions
    for func in info.failure_path_new_funcs:
        arg_names = set(a.name for a in func.args)
        unused_vars = find_unused_vars(func.body, info, target=arg_names)
        if len(unused_vars) == 0:
            continue
        indices = []
        for i, a in enumerate(func.args):
            if a.name in unused_vars:
                indices.append(i)
        rm_func[func.name] = indices
        # debug(func.name, ':', unused_vars, tag=MODULE_TAG)

    if len(rm_func) == 0:
        return inst, False

    res = CheckForFuncCall.do(inst, info, more, rm_func=rm_func).result
    for func in Function.directory.values():
        # if not func.is_used_in_bpf_code:
        #     continue
        tmp = CheckForFuncCall.do(func.body, info, more=None, func=func,
                rm_func=rm_func)
        func.body = tmp.result

    new_failure_paths = {}
    for path_id, path in info.failure_paths.items():
        tmp_block = Block(BODY)
        tmp_block.children = path
        tmp = CheckForFuncCall.do(tmp_block, info, more=None, rm_func=rm_func)
        new_failure_paths[path_id] = tmp.result.children
    info.failure_paths = new_failure_paths

    for func_name, indicies in rm_func.items():
        func = Function.directory[func_name]
        func.args = remove_indicies_from_arr(func.args, indicies)
    return res, True


def remove_unused_args(inst, info, more):
    # Check unused args until the search is stable
    new_inst, change = _do_remove_unused_args(inst, info, more)
    while change:
        new_inst, change = _do_remove_unused_args(new_inst, info, more)
