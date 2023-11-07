import clang.cindex as clang
from dfs import DFSPass
from log import debug, error, report


def _do_pass(bpf, all_declarations, info):
    d = DFSPass(bpf)
    for inst, _ in d:
        key = None
        if inst.kind == clang.CursorKind.CALL_EXPR:
            # step into the function
            func = inst.get_function_def()
            if func and not func.is_empty():
                _do_pass(func.body, all_declarations, info)
            key = inst.name
        elif inst.kind == clang.CursorKind.VAR_DECL:
            key = inst.type.spelling

        if key is not None:
            if key in all_declarations:
                all_declarations.remove(key)
            continue
        d.go_deep()

    # debug('List of declarations to remove:', all_declarations)
    return bpf


def remove_everything_not_used(bpf, info, more):
    all_declarations = [decl.name for decl in info.prog.declarations if hasattr(decl, 'name')]
    _do_pass(bpf, all_declarations, info)
    new_list = []
    for decl in info.prog.declarations:
        if not hasattr(decl, 'name'):
            new_list.append(decl)
            continue

        for name in all_declarations:
            if decl.name == name:
                remove = True
                break
        else:
            new_list.append(decl)
    info.prog.declarations = new_list
