import clang.cindex as clang
from log import debug
from instruction import *
from data_structure import *
from var_names import FAIL_FLAG_NAME, SEND_FLAG_NAME
from helpers.instruction_helper import add_flag_to_func, CHAR, ZERO, UINT, get_or_decl_ref
from passes.code_pass import Pass
from passes.clone import clone_pass


MODULE_TAG = '[Update Func Signiture]'


class UpdateCallInst(Pass):
    """
    Update the function calls inside a block of code. Make sure the add flags
    are passed when invoking the function.
    """
    def __init__(self, info):
        super().__init__(info)

    def _handle_call(self, inst, more):
        func = inst.get_function_def()
        if not func or func.is_empty():
            return inst

        # Check if the function being invoked needs to receive any flag
        ctx = ((func.calls_recv or func.calls_send) and
                not inst.has_flag(Function.CTX_FLAG))
        send = func.calls_send and not inst.has_flag(Function.SEND_FLAG)
        # func.may_succeed and 
        fail = (func.may_fail and
                not inst.has_flag(Function.FAIL_FLAG))
        if not (ctx or send or fail):
            return inst
        new_inst = clone_pass(inst)

        if ctx:
            assert func.change_applied & Function.CTX_FLAG != 0, 'The function call is determined to requier context pointer but the function signiture is not updated'
            new_inst.set_flag(Function.CTX_FLAG)
            new_inst.args.append(self.info.prog.get_ctx_ref())
            new_inst.set_modified(InstructionColor.ADD_ARGUMENT)
            # debug('add ctx ref to call:', new_inst.name, tag=MODULE_TAG)

        # Add send flag
        if send:
            assert func.change_applied & Function.SEND_FLAG != 0, 'Expect the function should already have the send flag on its argument list'
            sym = self.info.sym_tbl.lookup(SEND_FLAG_NAME)
            if self.current_function is None:
                flag, tmp_decl = get_or_decl_ref(self.info, SEND_FLAG_NAME,
                        CHAR, ZERO)
                assert not flag.type.is_pointer(), 'Expecting the flag to be a scalar on main function'
                self.declare_at_top_of_func.extend(tmp_decl)
                flag_ref = UnaryOp.build('&', flag)
            else:
                # Just pass the reference, the function must have received a
                # flag from the entry scope
                assert sym is not None and sym.type.is_pointer(), 'We have a function that does not receive the send flag!'
                flag_ref = Ref.from_sym(sym)
            new_inst.set_flag(Function.SEND_FLAG)
            new_inst.args.append(flag_ref)
            new_inst.set_modified(InstructionColor.ADD_ARGUMENT)

        # Add failure flag
        if fail:
            fail_flag, tmp_decl = get_or_decl_ref(self.info, FAIL_FLAG_NAME, UINT, ZERO)
            self.declare_at_top_of_func.extend(tmp_decl)
            if fail_flag.type.is_pointer():
                assert self.current_function is not None, 'Expecting to be inside a intermediate function'
                fail_flag_ref = fail_flag
            else:
                assert self.current_function is None, f'Expecting to be at the main function but at {self.current_fname}'
                fail_flag_ref = UnaryOp.build('&', fail_flag)
            new_inst.set_flag(Function.FAIL_FLAG)
            new_inst.args.append(fail_flag_ref)
            new_inst.set_modified(InstructionColor.ADD_ARGUMENT)
        return new_inst

    def process_current_inst(self, inst, more):
        if inst.kind == clang.CursorKind.CALL_EXPR:
            return self._handle_call(inst, more)
        return inst


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

    # func.may_succeed and 
    if func.may_fail and (func.change_applied & Function.FAIL_FLAG == 0):
        arg = StateObject(None)
        arg.name = FAIL_FLAG_NAME
        arg.type_ref = MyType.make_pointer(UINT)
        func.args.append(arg)
        func.change_applied |= Function.FAIL_FLAG
        scope = info.sym_tbl.scope_mapping.get(func.name)
        assert scope is not None
        scope.insert_entry(arg.name, arg.type_ref, clang.CursorKind.PARM_DECL, None)
        # debug('add param:', FAIL_FLAG_NAME, 'to', func.name)


def update_function_signature(inst, info):
    # First check function definitions and flags they receive
    for func in Function.directory.values():
        if not func.is_used_in_bpf_code:
            continue
        with info.sym_tbl.with_func_scope(func.name):
            _check_func_receives_all_the_flags(func, info)

    res = UpdateCallInst.do(inst, info).result
    for func in Function.directory.values():
        if not func.is_used_in_bpf_code:
            continue
        tmp = UpdateCallInst.do(func.body, info, func=func)
        func.body = tmp.result
    return res
