from dfs import DFSPass
from log import debug, error
from prune import should_process_this_cursor
from utility import report_on_cursor, PRIMITIVE_TYPES

from data_structure import MyType
import clang.cindex as clang


remember_unnamed_struct_name = {}
MODULE_TAG = '[SYM TBL GEN]'


def __collect_information_about_class(cursor, info):
    # map __class__ identifier to the class representing current scope -
    T = MyType.from_cursor_type(cursor.type)
    e = info.sym_tbl.insert_entry('__class__', T, cursor.kind, None)
    # override the name form __class__ to actual class name
    e.name = cursor.spelling
    # -------------------------------------------------------------------

    d = DFSPass(cursor, inside=True)
    class_name = cursor.spelling
    for c, l in d:
        if c.kind == clang.CursorKind.FIELD_DECL:
            T = MyType.from_cursor_type(c.type)
            info.sym_tbl.insert_entry(c.spelling, T, c.kind, None)
        elif c.kind == clang.CursorKind.CXX_METHOD:
            method_name = f'{class_name}_{c.spelling}'
            T = MyType.from_cursor_type(c.result_type)
            info.sym_tbl.insert_entry(method_name, T, c.kind, None)

            with info.sym_tbl.new_scope() as scope:
                info.sym_tbl.scope_mapping[method_name] = scope
                __collect_information_about_func(c, info)


def __collect_information_about_func(cursor, info):
    children = list(cursor.get_children())
    assert len(children) != 0

    T = MyType.from_cursor_type(cursor.type)
    e = info.sym_tbl.insert_entry('__func__', T, cursor.kind, None)
    e.name = cursor.spelling

    # Add function parameters to the scope
    for pos, arg in enumerate(cursor.get_arguments()):
        T = MyType.from_cursor_type(arg.type)
        e = info.sym_tbl.insert_entry(arg.spelling, T, arg.kind, arg)

    # TODO: Do I need to process the body of each functions?
    # body = children[-1]


def pass_over_global_variables(cursor, info):
    """
    Go through the global variables and add them to the top level scope
    """
    d = DFSPass(cursor)
    for c, l in d:
        if c.kind == clang.CursorKind.VAR_DECL:
            T = MyType.from_cursor_type(c.type)
            info.sym_tbl.insert_entry(c.spelling, T, c.kind, c)
        if c.kind == clang.CursorKind.TRANSLATION_UNIT:
            d.go_deep()


def build_sym_table(cursor, info):
    """
    Go through all the declarations of class, struct, function, fields, and
    variables.  Create scope for class and functions and add the fields or
    variables to the correct scope.

    This function does not explore the body of functions. This is postponed for
    later.
    """
    # Define the field of BPF context
    info.prog.set_bpf_context_struct_sym_tbl(info.sym_tbl)
    pass_over_global_variables(cursor, info)
    info.sym_tbl.current_scope = info.sym_tbl.global_scope

    info.sym_tbl.scope_mapping['__global__'] = info.sym_tbl.current_scope

    unnamed_struct_coutner = 0
    d = DFSPass(cursor)
    for c, l in d:
        if not (should_process_this_cursor(c) or c.kind == clang.CursorKind.TRANSLATION_UNIT):
            continue

        if c.kind == clang.CursorKind.CLASS_DECL:
            if not c.is_definition():
                continue

            scope_key = f'class_{c.spelling}'
            T = MyType.from_cursor_type(c.type)
            info.sym_tbl.insert_entry(scope_key, T, c.kind, None)

            with info.sym_tbl.new_scope() as scope:
                info.sym_tbl.scope_mapping[scope_key] = scope
                __collect_information_about_class(c, info)
            continue
        elif c.kind == clang.CursorKind.VAR_DECL and l > 1:
            # If it is a variable decleration and it is not a global variable
            T = MyType.from_cursor_type(c.type)
            info.sym_tbl.insert_entry(c.spelling, T, c.kind, None)
            continue
        elif c.kind == clang.CursorKind.FUNCTION_DECL:
            if not c.is_definition():
                continue

            scope_key = f'{c.spelling}'
            T = MyType.from_cursor_type(c.result_type)
            info.sym_tbl.insert_entry(scope_key, T, c.kind, c)

            with info.sym_tbl.new_scope() as scope:
                info.sym_tbl.scope_mapping[scope_key] = scope
                __collect_information_about_func(c, info)
            continue
        elif c.kind == clang.CursorKind.STRUCT_DECL:
            if not c.is_definition():
                continue
            if not c.spelling:
                # An unnamed struct
                scope_key = f'class_struct unnamed_{unnamed_struct_coutner}'
                unnamed_struct_coutner += 1
                remember_unnamed_struct_name[c.get_usr()] = scope_key
            else:
                scope_key = f'class_struct {c.spelling}'
            T = MyType.from_cursor_type(c.type)
            info.sym_tbl.insert_entry(scope_key, T, c.kind, c)
            with info.sym_tbl.new_scope() as scope:
                info.sym_tbl.scope_mapping[scope_key] = scope
                __collect_information_about_class(c, info)
            continue
        elif c.kind == clang.CursorKind.TYPEDEF_DECL:
            # Typedef is handled in multiple cases
            under_type = c.underlying_typedef_type
            if under_type.kind == clang.TypeKind.POINTER:
                # It is defining a pointer type (possibly a function pointer)
                # TODO: do I need to know something about this? (probably)
                continue
            elif under_type.kind == clang.TypeKind.TYPEDEF:
                # TODO: udpate the symbol table ?
                continue
            elif under_type.kind == clang.TypeKind.ELABORATED:
                # TODO: remember that this type is same as the struct/union/enum/...
                continue
            elif under_type.kind in PRIMITIVE_TYPES:
                # TODO: udpate the symbol table ?
                continue
            elif under_type.kind == clang.TypeKind.FUNCTIONPROTO:
                # TODO: udpate the symbol table ?
                continue
            elif under_type.kind == clang.TypeKind.CONSTANTARRAY:
                # TODO: udpate the symbol table ?
                continue
            elif "it is defining an anonymous type":
                scope_key = f'class_{c.spelling}'
                x = c.underlying_typedef_type
                x = x.get_declaration()
                usr = x.get_usr()
                equivalent_scope_key = remember_unnamed_struct_name.get(usr, None)
                if equivalent_scope_key is None:
                    report_on_cursor(c)
                    debug(MODULE_TAG, 'Underlying type:', under_type.spelling, under_type.kind)
                    error(MODULE_TAG, f'It seems that a unnamed type (struct, union, ...) was ignored ({x})')
                    continue
                equivalent_scope = info.sym_tbl.scope_mapping[equivalent_scope_key]
                info.sym_tbl.scope_mapping[scope_key] = equivalent_scope
                info.sym_tbl.insert_entry(scope_key, T, c.kind, c)
                equiv_sym = info.sym_tbl.lookup(equivalent_scope_key)
                info.sym_tbl.insert(equiv_sym)
            continue

        d.go_deep()
