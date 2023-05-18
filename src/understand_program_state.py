import sys
import clang.cindex as clang

from utility import (find_elem, get_code, generate_struct_with_fields,
        PRIMITIVE_TYPES, report_on_cursor)
from bpf import SK_SKB_PROG
from data_structure import *


def generate_decleration_for(cursor):
    """
    cursor is a class, struct, enum, ...
    return a list of strings having codes for defining the types needed.
    """
    type_name = cursor.spelling

    # List of type dependencies for this specific type
    decl = []

    if cursor.type.kind == clang.TypeKind.RECORD:
        # Go through the fields, add any dependencies field might have, then
        # define a struct for it.
        fields, new_decl = extract_state(cursor)
        decl += new_decl
        r = Record(type_name, fields)
        decl.append(r)
    elif cursor.type.kind == clang.TypeKind.ELABORATED:
        # For enum, union, typedef
        c = cursor.type.get_declaration()
        d = generate_decleration_for(c)
        decl.extend(d)
        decl.append(Elaborate(c))
    elif cursor.type.kind == clang.TypeKind.ENUM:
        # No further deps
        return []
    elif cursor.type.kind == clang.TypeKind.TYPEDEF:
        # print(cursor.spelling)
        if not cursor.kind.is_declaration():
            t = cursor.type.get_declaration()
            # print(t)
            # report_on_cursor(t)
        else:
        # if cursor.kind.is_declaration():
            t = cursor.underlying_typedef_type
        under_kind = t.kind
        # else:
        #     c = cursor.type.get_declaration()
        #     report_on_cursor(c)
        #     print('Typedef if not declaration, I do not udnerstand this.', file=sys.stderr)
        #     under_kind = cursor.kind
        if under_kind in PRIMITIVE_TYPES:
            # No further type decleration needed
            return []
        for c in cursor.get_children():
            decl += generate_decleration_for(c)
    else:
        print('Unexpected! ' + str(cursor.type.kind), file=sys.stderr)

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
            obj.type_ref = d[-1]
        states.append(obj)
    return states, decl


def get_state_for(cursor):
    """
    Get state definition and needed decleration for a variable or parameter
    declartion
    """
    states = []
    decl = []
    k = cursor.kind
    if k == clang.CursorKind.PARM_DECL:
        states.append(StateObject(cursor))
        decl = generate_decleration_for(cursor) 
    elif k == clang.CursorKind.VAR_DECL:
        obj = StateObject(cursor)
        states.append(obj)
        decl = generate_decleration_for(cursor)
        if cursor.type.kind in (clang.TypeKind.RECORD, clang.TypeKind.ELABORATED) and decl:
            obj.type_ref = d[-1]
    else:
        raise Exception('Not implemented! ' + str(k))
    return states, decl
