"""
Some object representing internal types
"""
import clang.cindex as clang
from my_type import MyType
from var_names import *


def __define(name):
    """
    A helper for creating MyType objects for internal types Kashk uses.
    """
    simple_type = MyType.make_simple(f'struct {name}', clang.TypeKind.RECORD)
    ptr_to_type = MyType.make_pointer(simple_type)
    return simple_type, ptr_to_type


SHARED_STRUCT_TYPE, SHARED_OBJ_PTR = __define(SHARED_STATE_STRUCT_NAME)
FLOW_ID_TYPE, FLOW_ID_PTR = __define(FIVE_TUPLE_STRUCT_NAME)
SOCK_STATE_TYPE, SOCK_STATE_PTR = __define(SOCK_STATE_STRUCT_NAME)
