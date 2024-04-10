"""
Some object representing internal types
"""
import clang.cindex as clang
from my_type import MyType
from var_names import *

SHARED_STRUCT_TYPE = MyType.make_simple(f'struct {SHARED_STATE_STRUCT_NAME}', clang.TypeKind.RECORD)
SHARED_OBJ_PTR = MyType.make_pointer(SHARED_STRUCT_TYPE)

FLOW_ID_TYPE = MyType.make_simple(f'struct {FIVE_TUPLE_STRUCT_NAME}', clang.TypeKind.RECORD)
FLOW_ID_PTR  = MyType.make_pointer(FLOW_ID_TYPE)
