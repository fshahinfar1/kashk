import clang.cindex as clang
from utility import get_actual_type
from dfs import DFSPass
from log import debug, error, report
from data_structure import Record


MODULE_TAG = '[Remove]'


def _do_pass(bpf, all_declarations, info):
    d = DFSPass(bpf)
    for inst, _ in d:
        keys = None
        if inst.kind == clang.CursorKind.CALL_EXPR:
            # step into the function
            func = inst.get_function_def()
            if func and not func.is_empty():
                _do_pass(func.body, all_declarations, info)
            keys = [inst.name,]
        elif inst.kind == clang.CursorKind.VAR_DECL:
            type_name = get_actual_type(inst.type).spelling
            keys = [type_name,]
            if inst.type.is_record():
                type_name2 = type_name[len('struct '):]
                decl = Record.directory.get(type_name2)
                if decl:
                    for field in decl.fields:
                        if field.type_ref.is_record():
                            keys.append(get_actual_type(field.type_ref).spelling)
                else:
                    # debug(MODULE_TAG, 'Did not found decleration for', type_name2)
                    pass


        if keys is not None:
            for k in keys:
                if k in all_declarations:
                    all_declarations.remove(k)
            continue
        d.go_deep()
    return bpf


def remove_everything_not_used(bpf, info, more):
    all_declarations = [decl.get_name() for decl in info.prog.declarations if hasattr(decl, 'get_name')]
    _do_pass(bpf, all_declarations, info)
    new_list = []
    # debug(MODULE_TAG, 'List of declarations to remove:', all_declarations)
    for decl in info.prog.declarations:
        if not hasattr(decl, 'get_name'):
            new_list.append(decl)
            continue

        for name in all_declarations:
            if decl.get_name() == name:
                remove = True
                break
        else:
            new_list.append(decl)
    info.prog.declarations = new_list
