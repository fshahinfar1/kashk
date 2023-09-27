import sys
import clang.cindex as clang

from log import *
from utility import (find_elem, get_code, generate_struct_with_fields,
        PRIMITIVE_TYPES, report_on_cursor, get_actual_type)
from bpf import SK_SKB_PROG
from data_structure import *

from prune import should_process_this_cursor, get_namespace_of_cursor


MODULE_TAG = '[Program State]'


# TODO: I have messed up finding the right type, I should refactor, rewrite
# this function.
def generate_decleration_for(cursor):
    """
    cursor is a class, struct, enum, ...
    return a list of strings having codes for defining the types needed.
    """

    if not should_process_this_cursor(cursor):
        return []

    T = get_actual_type(cursor.type)

    if T.kind in PRIMITIVE_TYPES:
        return []

    c = T.get_declaration()
    if c is None:
        error(MODULE_TAG, f'Failed to find the definition for {T.spelling} [1]')
        return []
    c2 = c.get_definition()
    if c2 is None:
        # error(MODULE_TAG, f'Failed to find the definition for {T.spelling} [2]')
        # report_on_cursor(cursor)
        # report_on_cursor(c)
        report(f'Assume "{c.type.spelling}" is a private type.')
        c2 = c

    cursor = c2
    T = cursor.type
    type_name = T.spelling

    # List of type dependencies for this specific type
    decl = []

    if T.kind in PRIMITIVE_TYPES:
        return decl

    if T.kind == clang.TypeKind.RECORD:
        #TODO: what should I do about it???
        if type_name.startswith('struct '):
            type_name = type_name[len('struct '):]
        # Go through the fields, add any dependencies field might have, then
        # define a struct for it.
        fields, new_decl = extract_state(cursor)
        decl += new_decl
        r = Record(type_name, fields)
        decl.append(r)
    elif T.kind == clang.TypeKind.ELABORATED:
        decl.append(Elaborate(c))
    elif T.kind == clang.TypeKind.ENUM:
        # TODO: No further deps?
        return []
    elif T.kind == clang.TypeKind.TYPEDEF:
        x = c.underlying_typedef_type
        x = x.get_declaration()
        return generate_decleration_for(x)
    else:
        error('Unexpected! ' + str(cursor.type.kind))

    return decl


def extract_state(cursor):
    """
    Extract fields and dependant type declartion from a class or struct
    """
    states = []
    decl = []
    for c in cursor.type.get_fields():
        obj = StateObject(c)
        if c.type.kind in (clang.TypeKind.RECORD, clang.TypeKind.ELABORATED):
            # Check that the field is not a ASIO type
            ns = get_namespace_of_cursor(c)
            if ns == 'asio':
                continue

            d = generate_decleration_for(c)
            decl += d
        states.append(obj)
    return states, decl


def get_state_for(cursor):
    """
    Get state definition and needed decleration for a variable or parameter
    declartion
    """
    states = []
    decl = []

    obj = StateObject(cursor)
    states.append(obj)
    decl = generate_decleration_for(cursor)

    return states, decl
