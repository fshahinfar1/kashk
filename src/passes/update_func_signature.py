import clang.cindex as clang
from log import debug
from instruction import *
from data_structure import *
from var_names import FAIL_FLAG_NAME, SEND_FLAG_NAME


def _check_func_receives_all_the_flags(func, info):
    """
    Check if function receives flags it need through its arguments
    """
    # debug("check func", func.name, 'send or recv?', func.calls_send, func.calls_recv)
    if (func.calls_send or func.calls_recv) and (func.change_applied & Function.CTX_FLAG == 0):
        # Add the BPF context to its arguemt
        add_flag_to_func(Function.CTX_FLAG, func, info)
    if func.calls_send and (func.change_applied & Function.SEND_FLAG == 0):
        # Add the send flag
        arg = StateObject(None)
        arg.name = SEND_FLAG_NAME
        arg.type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
        func.args.append(arg)
        func.change_applied |= Function.SEND_FLAG
        scope = info.sym_tbl.scope_mapping.get(func.name)
        assert scope is not None
        scope.insert_entry(arg.name, arg.type_ref, clang.CursorKind.PARM_DECL, None)

    if func.may_succeed and func.may_fail and (func.change_applied & Function.FAIL_FLAG == 0):
        arg = StateObject(None)
        arg.name = FAIL_FLAG_NAME
        arg.type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
        func.args.append(arg)
        func.change_applied |= Function.FAIL_FLAG
        scope = info.sym_tbl.scope_mapping.get(func.name)
        assert scope is not None
        scope.insert_entry(arg.name, arg.type_ref, clang.CursorKind.PARM_DECL, None)
        # debug('add param:', FAIL_FLAG_NAME, 'to', func.name)


def update_function_signature(info):
    # First check function definitions and flags they receive
    for func in Function.directory.values():
        if not func.is_used_in_bpf_code:
            continue
        with info.sym_tbl.with_func_scope(func.name):
            _check_func_receives_all_the_flags(func, info)
