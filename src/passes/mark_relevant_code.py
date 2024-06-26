from contextlib import contextmanager
import clang.cindex as clang
from dfs import DFSPass
from log import *
from utility import PRIMITIVE_TYPES, get_actual_type
from prune import should_process_this_cursor

from parser.understand_program_state import generate_decleration_for
from data_structure import Record

MODULE_TAG = '[Mark Used Func]'
_has_processed = set()
current_function = None


@contextmanager
def set_current_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield func
    finally:
        current_function = tmp


def _find_type_decl_class(name, info):
    scope_key = f'class_{name}'
    entry = info.sym_tbl.sk_state_scope.lookup(scope_key)
    if entry is None:
        # debug(f'did not found type: {name}')
        # debug(list(info.sym_tbl.sk_state_scope.symbols.keys()))
        return []
    cursor = entry.ref
    if cursor is None or not should_process_this_cursor(cursor):
        return []
    assert cursor is not None
    decls = generate_decleration_for(cursor)
    # debug(cursor.spelling)
    # debug([d.name for d in decls])
    return decls


def _find_type_decl(name, info):
    tmp = _find_type_decl_class(name, info)
    if tmp:
        return tmp
    return []


__analysed_types = set()
def _add_type_to_declarations(T, info):
    T = get_actual_type(T)
    if T is None or T.kind in PRIMITIVE_TYPES or T.spelling in _has_processed:
        return
    type_name = T.spelling
    if type_name in __analysed_types:
        return
    __analysed_types.add(type_name)
    decls = _find_type_decl(type_name, info)
    for decl in decls:
        if decl.is_used_in_bpf_code or decl.name in _has_processed:
            continue
        decl.is_used_in_bpf_code = True
        info.prog.declarations.append(decl)
        _has_processed.add(decl.name)
        if isinstance(decl, Record):
            for f in decl.fields:
                T = f.type
                _add_type_to_declarations(T, info)


def _do_pass(inst, info, more):
    d = DFSPass(inst)
    for inst, _ in d:
        if inst.kind == clang.CursorKind.CALL_EXPR:
            func = inst.get_function_def()
            if func:
                if not func.is_empty() and not func.is_used_in_bpf_code:
                    # debug(MODULE_TAG, 'Add func:', func.name)
                    # Only include functions that have concrete implementation
                    func.is_used_in_bpf_code = True
                    info.prog.declarations.insert(0, func)
                    # report(MODULE_TAG, 'Function:', func.name)

                # Check param types and mark their definition useful
                for arg in func.get_arguments():
                    _add_type_to_declarations(arg.type_ref, info)
                # Continue processing the code reachable inside the function
                with set_current_func(func):
                    _do_pass(func.body, info, None)
            else:
                debug('did not found function struct for', inst.name)
            # continue
        elif inst.kind == clang.CursorKind.VAR_DECL:
            _add_type_to_declarations(inst.type, info)
        elif inst.kind == clang.CursorKind.DECL_REF_EXPR:
            # Global variables do not have declerations on function scope. If
            # we do not have this we may miss them.
            _add_type_to_declarations(inst.type, info)
        elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
            _add_type_to_declarations(inst.type, info)
            for o in inst.owner:
                _do_pass(o, info, more)

        d.go_deep()

def mark_relevant_code(bpf, info, more):
    """
    Mark used functions and types. This helps to only consider the relevant
    codes and data-types when processing.
    """
    # global _has_processed
    # _has_processed = set()
    with set_current_func(None):
        _do_pass(bpf, info, None)
