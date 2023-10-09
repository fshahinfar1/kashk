import clang.cindex as clang
from dfs import DFSPass

def _do_pass(inst, info, more):
    d = DFSPass(inst)
    for inst, _ in d:
        if inst.kind == clang.CursorKind.CALL_EXPR:
            func = inst.get_function_def()
            if func:
                func.is_used_in_bpf_code = True
                _do_pass(func.body, info, None)
            continue
        d.go_deep()

def mark_used_funcs(bpf, info, more):
    _do_pass(bpf, info, None)

