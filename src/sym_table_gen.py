from dfs import DFSPass
from log import debug, error
from prune import should_process_this_cursor
from utility import report_on_cursor

import clang.cindex as clang
import pprint


def __collect_information_about_class(cursor, info):
    # map __class__ identifier to the class representing current scope -
    e = info.sym_tbl.insert_entry('__class__', cursor.type, cursor.kind, cursor)
    # override the name form __class__ to actual class name
    e.name = cursor.spelling
    # -------------------------------------------------------------------

    d = DFSPass(cursor, inside=True)
    class_name = cursor.spelling
    for c, l in d:
        if c.kind == clang.CursorKind.FIELD_DECL:
            info.sym_tbl.insert_entry(c.spelling, c.type, c.kind, c)
        elif c.kind == clang.CursorKind.CXX_METHOD:
            method_name = f'{class_name}_{c.spelling}'
            info.sym_tbl.insert_entry(method_name, c.result_type, c.kind, c)

            with info.sym_tbl.new_scope() as scope:
                info.sym_tbl.scope_mapping[method_name] = scope
                __collect_information_about_func(c, info)


def __collect_information_about_func(cursor, info):
    children = list(cursor.get_children())
    assert len(children) != 0

    # Add function parameters to the scope
    for pos, arg in enumerate(cursor.get_arguments()):
        e = info.sym_tbl.insert_entry(arg.spelling, arg.type, arg.kind, arg)
        e.param_pos = pos

    # TODO: Do I need to process the body of each functions?
    # body = children[-1]


def pass_over_global_variables(cursor, info):
    """
    Go through the global variables and add them to the top level scope
    """
    d = DFSPass(cursor)
    for c, l in d:
        if c.kind == clang.CursorKind.VAR_DECL:
            info.sym_tbl.insert_entry(c.spelling, c.type, c.kind, c)
        if c.kind == clang.CursorKind.TRANSLATION_UNIT:
            d.go_deep()


def build_sym_table(cursor, info):
    """
    Go through all the declaration of class, function, fields, and variables.
    Create scope for class and functions and add the fields or variables to the
    correct scope.

    This function does not explore the body of functions. This is post-poned
    for later.
    """
    pass_over_global_variables(cursor, info)
    info.sym_tbl.current_scope = info.sym_tbl.global_scope

    info.sym_tbl.scope_mapping['__global__'] = info.sym_tbl.current_scope

    d = DFSPass(cursor)
    for c, l in d:
        # debug('|  '*l + f'+- {c.spelling} {c.kind}')

        if c.kind == clang.CursorKind.CLASS_DECL:
            if not c.is_definition():
                continue

            scope_key = f'class_{c.spelling}'
            info.sym_tbl.insert_entry(scope_key, c.type, c.kind, c)

            with info.sym_tbl.new_scope() as scope:
                info.sym_tbl.scope_mapping[scope_key] = scope
                __collect_information_about_class(c, info)
            continue
        elif c.kind == clang.CursorKind.VAR_DECL and l > 1:
            # If it is a variable decleration and it is not a global variable
            info.sym_tbl.insert_entry(c.spelling, c.type, c.kind, c)
            continue
        elif c.kind == clang.CursorKind.FUNCTION_DECL:
            if not c.is_definition():
                continue

            # scope_key = f'func_{c.spelling}'
            scope_key = f'{c.spelling}'
            info.sym_tbl.insert_entry(scope_key, c.result_type, c.kind, c)

            with info.sym_tbl.new_scope() as scope:
                info.sym_tbl.scope_mapping[scope_key] = scope
                __collect_information_about_func(c, info)
            continue

        # Should we go deeper and investigate the children of this object?
        if (should_process_this_cursor(c)
                or c.kind == clang.CursorKind.TRANSLATION_UNIT):
            d.go_deep()
