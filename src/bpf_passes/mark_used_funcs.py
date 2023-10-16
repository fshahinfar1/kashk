import clang.cindex as clang
from dfs import DFSPass
from log import *
from utility import PRIMITIVE_TYPES, get_actual_type

from understand_program_state import generate_decleration_for

# TODO: what if a name of a struct is changed using a typedef ?

def _find_type_decl_class(name, info):
    scope_key = f'class_{name}'
    entry = info.sym_tbl.global_scope.lookup(scope_key)
    if entry is None:
        # debug(list(info.sym_tbl.global_scope.symbols.keys()))
        return []
    cursor = entry.ref
    assert cursor is not None
    decls = generate_decleration_for(cursor)
    return decls

def _find_type_decl(name, info):
    tmp = _find_type_decl_class(name, info)
    if tmp:
        return tmp

    entry = info.sym_tbl.global_scope.lookup(name)
    if entry is None:
        debug(f'did not found type: {name}')
    cursor = entry.ref
    assert cursor is not None
    decls = generate_decleration_for(cursor)
    # debug(name, decls)
    return decls

_has_processed = set()
def _add_type_to_declarations(T, info):
    T = get_actual_type(T)
    if T is None or T.kind in PRIMITIVE_TYPES or T.spelling in _has_processed:
        return
    type_name = T.spelling
    decls = _find_type_decl(type_name, info)
    for decl in decls:
        if decl.name in _has_processed:
            continue
        decl.is_used_in_bpf_code = True
        info.prog.declarations.append(decl)
        _has_processed.add(decl.name)


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
                    _add_type_to_declarations(arg.type_ref, info)
                # Continue processing the code reachable inside the function
                _do_pass(func.body, info, None)
            continue
        elif inst.kind == clang.CursorKind.VAR_DECL:
            _add_type_to_declarations(inst.type, info)
        d.go_deep()

def mark_used_funcs(bpf, info, more):
    _do_pass(bpf, info, None)
