import clang.cindex as clang
from dfs import DFSPass
from log import *

# TODO: what if a name of a struct is changed using a typedef ?

def _find_type_decl(name, info):
    for decl in info.prog.declarations:
        if decl.get_name() == name:
            return decl
    debug(f'did not found type: {name}')
    return None

def _do_pass(inst, info, more):
    d = DFSPass(inst)
    for inst, _ in d:
        if inst.kind == clang.CursorKind.CALL_EXPR:
            func = inst.get_function_def()
            if func:
                if not func.is_empty() and not func.is_used_in_bpf_code:
                    # Only include functions that have concrete implementation
                    func.is_used_in_bpf_code = True
                    info.prog.declarations.append(func)

                # Check param types and mark their definition useful
                for arg in func.get_arguments():
                    decl = _find_type_decl(arg.type, info)
                    if decl and not decl.is_used_in_bpf_code:
                        decl.is_used_in_bpf_code = True
                        info.prog.declarations.append(decl)

                # Continue processing the code reachable inside the function
                _do_pass(func.body, info, None)
            continue
        elif inst.kind == clang.CursorKind.VAR_DECL:
            type_name = inst.type.spelling
            decl = _find_type_decl(type_name, info)
            if decl and not decl.is_used_in_bpf_code:
                decl.is_used_in_bpf_code = True
                info.prog.declarations.append(decl)
                continue
        d.go_deep()

def mark_used_funcs(bpf, info, more):
    _do_pass(bpf, info, None)

    # for decl in info.prog.declarations:
    #     print(decl)

