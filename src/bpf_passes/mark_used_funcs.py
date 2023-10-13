import clang.cindex as clang
from dfs import DFSPass
from log import *
from utility import PRIMITIVE_TYPES

from understand_program_state import get_state_for

# TODO: what if a name of a struct is changed using a typedef ?

def _find_type_decl(name, info):
    scope_key = f'class_{name}'
    entry = info.sym_tbl.global_scope.lookup(scope_key)
    if entry is None:
        debug(f'did not found type: {name}')
        return None
    cursor = entry.ref
    assert cursor is not None
    state, decls = get_state_for(cursor)
    return decls


def _get_underlying_type(T):
    while T.is_pointer() or T.is_array():
        if T.is_pointer():
            T = T.get_pointee()
        elif T.is_array():
            T = T.element_type
    if T.is_func_proto():
        return None
    return T


_has_processed = set()
def _add_type_to_declarations(T, info):
    T = _get_underlying_type(T)
    if T is None or T in PRIMITIVE_TYPES or T.spelling in _has_processed:
        return
    type_name = T.spelling
    decls = _find_type_decl(type_name, info)
    if decls is None:
        return
    for decl in decls:
        decl.is_used_in_bpf_code = True
        info.prog.declarations.append(decl)
        assert decl.name not in _has_processed
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
