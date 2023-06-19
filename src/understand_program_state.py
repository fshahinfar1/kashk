import sys
import clang.cindex as clang

from utility import (find_elem, get_code, generate_struct_with_fields,
        PRIMITIVE_TYPES, report_on_cursor)
from bpf import SK_SKB_PROG
from data_structure import *

from prune import should_process_this_cursor


# TODO: I have messed up finding the right type, I should refactor, rewrite
# this function.
def generate_decleration_for(cursor):
    """
    cursor is a class, struct, enum, ...
    return a list of strings having codes for defining the types needed.
    """

    if not should_process_this_cursor(cursor):
        return []

    orig = cursor

    T = cursor.type
    if T.kind == clang.TypeKind.POINTER:
        T = T.get_pointee()
    if T.kind in PRIMITIVE_TYPES:
        return []
    c = T.get_declaration()
    if c is None:
        error(f'Failed to find the definition for {T.spelling}')
        return []
    c = c.get_definition()
    if c is None:
        error(f'Failed to find the definition for {T.spelling}')
        return []
    cursor = c
    T = cursor.type


    type_name = T.spelling

    # List of type dependencies for this specific type
    decl = []

    if T.kind in PRIMITIVE_TYPES:
        return decl

    if T.kind == clang.TypeKind.RECORD:
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
        pass
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
            d = generate_decleration_for(c)
            decl += d
            # if d:
            #     obj.type_ref = d[-1]
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
    # if cursor.type.kind in (clang.TypeKind.RECORD, clang.TypeKind.ELABORATED) and decl:
    #     obj.type_ref = decl[-1]

    return states, decl
