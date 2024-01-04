from dfs import DFSPass
from log import debug, error, report
from prune import should_process_this_cursor
from utility import report_on_cursor, PRIMITIVE_TYPES, try_get_definition

from data_structure import Function, Enum

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
            # TODO: I do not care about methods now
            continue
            # method_name = f'{class_name}_{c.spelling}'
            # T = MyType.from_cursor_type(c.result_type)
            # info.sym_tbl.insert_entry(method_name, T, c.kind, None)

            # with info.sym_tbl.new_scope() as scope:
            #     info.sym_tbl.scope_mapping[method_name] = scope
            #     __collect_information_about_func(c, info)


def __collect_information_about_func(cursor, info):
    T = MyType.from_cursor_type(cursor.type)
    e = info.sym_tbl.insert_entry('__func__', T, cursor.kind, None)
    e.name = cursor.spelling

    # Add function parameters to the scope
    for pos, arg in enumerate(cursor.get_arguments()):
        if arg.type.kind == clang.TypeKind.TYPEDEF:
            decl = arg.type.get_declaration()
        T = MyType.from_cursor_type(arg.type)
        e = info.sym_tbl.insert_entry(arg.spelling, T, arg.kind, arg)


def __pass_over_global_variables(cursor, info):
    """
    Go through the global variables and add them to the top level scope
    """
    d = DFSPass(cursor)
    for c, l in d:
        if c.kind == clang.CursorKind.VAR_DECL:
            if not should_process_this_cursor(c):
                continue
            T = MyType.from_cursor_type(c.type)
            info.sym_tbl.insert_entry(c.spelling, T, c.kind, c)
        elif c.kind == clang.CursorKind.TRANSLATION_UNIT:
            # Only go deep on the translation unit. we just want global
            # variables.
            d.go_deep()


def __remember_func_for_further_proc(cursor, info):
    # Check if we have inserted an entry for this function before
    key = cursor.spelling
    know_previous_def_of_func = False
    if key in Function.func_cursor:
        func_def_cursor = Function.func_cursor[key]
        know_previous_def_of_func = func_def_cursor.is_definition()
    func_decl = cursor
    if not func_decl.is_definition():
        tmp = func_decl.get_definition()
        if tmp:
            func_decl = tmp
    if know_previous_def_of_func:
        if func_decl.is_definition():
            if func_decl == func_def_cursor:
                # This is the same definition we already know about
                return
            else:
                error(MODULE_TAG, f'Multiple definition for function {key} is found!')
                return
        else:
            # We already know a definition and do not care about this cursor.
            return
    else:
        Function.func_cursor[key] = func_decl


def __function_decl(cursor, info):
    assert cursor.kind == clang.CursorKind.FUNCTION_DECL
    __remember_func_for_further_proc(cursor, info)

    scope_key = f'{cursor.spelling}'
    if scope_key in info.sym_tbl.scope_mapping:
        return
    T = MyType.from_cursor_type(cursor.result_type)
    info.sym_tbl.insert_entry(scope_key, T, clang.CursorKind.FUNCTION_DECL, None)

    with info.sym_tbl.new_scope() as scope:
        info.sym_tbl.scope_mapping[scope_key] = scope
        __collect_information_about_func(cursor, info)


def __enum_decl(cursor, info):
    assert cursor.kind == clang.CursorKind.ENUM_DECL
    enum = Enum.from_cursor(cursor)
    scope_key = enum.get_name()
    if scope_key in info.sym_tbl.scope_mapping:
        return
    enum.update_symbol_table(info.sym_tbl)


def __pass_over_source_file(cursor, info):
    unnamed_struct_coutner = 0
    d = DFSPass(cursor)
    # d: dfs object
    # c: cursor object
    # l: level (int)
    for c, l in d:
        # NOTE: I want to create a structure even for functions that are not in
        # libraries. That is why it is before `should_process_this_cursor`
        # check
        if c.kind == clang.CursorKind.FUNCTION_DECL:
            __function_decl(c, info)
            continue
        elif c.kind == clang.CursorKind.ENUM_DECL:
            __enum_decl(c, info)
            continue
        elif c.kind == clang.CursorKind.CLASS_DECL:
            scope_key = f'class_{c.spelling}'
            if info.sym_tbl.lookup(scope_key) is not None:
                # report(f'The class {scope_key} is declared multiple times, ignoring')
                continue
            T = MyType.from_cursor_type(c.type)
            info.sym_tbl.insert_entry(scope_key, T, c.kind, None)

            if c.is_definition():
                with info.sym_tbl.new_scope() as scope:
                    info.sym_tbl.scope_mapping[scope_key] = scope
                    __collect_information_about_class(c, info)
            continue
        elif c.kind == clang.CursorKind.VAR_DECL and l > 1:
            # If it is a variable decleration and it is not a global variable
            T = MyType.from_cursor_type(c.type)
            info.sym_tbl.insert_entry(c.spelling, T, c.kind, None)
            continue
        elif c.kind == clang.CursorKind.STRUCT_DECL:
            c = try_get_definition(c)
            if not c.spelling:
                # An unnamed struct
                scope_key = f'class_struct unnamed_{unnamed_struct_coutner}'
                unnamed_struct_coutner += 1
                remember_unnamed_struct_name[c.get_usr()] = scope_key
            else:
                scope_key = f'class_struct {c.spelling}'
            if info.sym_tbl.lookup(scope_key) is not None:
                # report(f'The struct {scope_key} is declared multiple time, ignoring')
                continue
            T = MyType.from_cursor_type(c.type)
            info.sym_tbl.insert_entry(scope_key, T, c.kind, c)
            if c.is_definition():
                with info.sym_tbl.new_scope() as scope:
                    info.sym_tbl.scope_mapping[scope_key] = scope
                    __collect_information_about_class(c, info)
            continue
        elif c.kind == clang.CursorKind.TYPEDEF_DECL:
            # Typedef is handled in multiple cases
            under_type = c.underlying_typedef_type
            if under_type.kind == clang.TypeKind.RECORD:
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
            else:
                key = c.spelling
                assert key
                T = MyType.from_cursor_type(c.type)
                info.sym_tbl.global_scope.insert_entry(key, T, c.kind, c)
                # debug('Elaborate Type:', key)
            continue

        d.go_deep()


def process_source_file(cursor, info):
    """
    Go through all the declarations of class, struct, function, fields, and
    variables.  Create scope for class and functions and add the fields or
    variables to the correct scope.

    This function does not explore the body of functions. This is postponed for
    later.
    """
    # NOTE: there is a very silly but important note about global scopes:
    #   global_scope: the scope used for keep a state for a single connection. Information not shared with other connections.
    #   shared scope: the scope shared between all connections
    # Global variables belong to the shared scope
    info.sym_tbl.current_scope = info.sym_tbl.shared_scope
    __pass_over_global_variables(cursor, info)
    info.sym_tbl.current_scope = info.sym_tbl.global_scope
    __pass_over_source_file(cursor, info)


def build_sym_table(cursor, info):
    """
    Boot strap the symbol table
    @param cursor: the main file AST
    """
    # Define the field of BPF context
    info.sym_tbl.current_scope = info.sym_tbl.global_scope
    info.sym_tbl.scope_mapping['__global__'] = info.sym_tbl.current_scope
    info.prog.set_bpf_context_struct_sym_tbl(info.sym_tbl)
    process_source_file(cursor, info)
