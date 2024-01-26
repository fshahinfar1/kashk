import itertools
from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from utility import indent
from template import prepare_meta_data
from data_structure import *
from instruction import *

from sym_table import SymbolTableEntry
from passes.pass_obj import PassObject

from code_gen import gen_code

from passes.bpf_passes.transform_vars import FAIL_FLAG_NAME


MODULE_TAG = '[Fallback Pass]'

current_function = None
cb_ref = CodeBlockRef()
_has_processed = set()
declare_at_top_of_func = []

ZERO = Literal('0', clang.CursorKind.INTEGER_LITERAL)


@contextmanager
def _new_top_func_declare_context():
    global declare_at_top_of_func
    tmp = declare_at_top_of_func
    declare_at_top_of_func = []
    try:
        yield declare_at_top_of_func
    finally:
        declare_at_top_of_func = tmp


class After:
    def __init__(self, box):
        self.box = box


@contextmanager
def remember_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield None
    finally:
        current_function = tmp


def _set_failure_flag(failure_number, is_pointer=False):
    int_inst = Literal(str(failure_number), clang.CursorKind.INTEGER_LITERAL)
    ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
    ref.name = FAIL_FLAG_NAME
    if is_pointer:
        ref.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
        ref = UnaryOp.build('*', ref)
    else:
        ref.type = BASE_TYPES[clang.TypeKind.SCHAR]
    # Assign
    set_failuer = BinOp.build(ref, '=', int_inst)
    return set_failuer


def _decl_failure_flag_on_stack(info):

    T = BASE_TYPES[clang.TypeKind.SCHAR]
    flag_decl = VarDecl(None)
    flag_decl.name = FAIL_FLAG_NAME
    flag_decl.type = T
    flag_decl.init.add_inst(ZERO)

    declare_at_top_of_func.append(flag_decl)
    flag_decl.update_symbol_table(info.sym_tbl)


def _generate_failure_flag_check_in_main_func_if_else(flag_ref, func, info):
    current_function = None
    first_failure_case = None
    prev_failure_case = None
    decl = []

    for failure_number in set(func.path_ids):
        # TODO: change declaration to a dictionary instead of array
        meta = info.user_prog.declarations[failure_number-1]
        prepare_meta_code, tmp_decl = prepare_meta_data(failure_number, meta, info)
        decl.extend(tmp_decl)

        # Check the failure number
        int_literal = Literal(str(failure_number), clang.CursorKind.INTEGER_LITERAL)
        cond = BinOp.build(flag_ref, '==', int_literal)
        if_inst = ControlFlowInst.build_if_inst(cond)
        if_inst.body.extend_inst(prepare_meta_code)
        if_inst.body.add_inst(ToUserspace.from_func_obj(current_function))

        if prev_failure_case is not None:
            prev_failure_case.other_body.add_inst(if_inst)
        else:
            first_failure_case = if_inst
        prev_failure_case = if_inst
    return_stmt = first_failure_case
    return return_stmt, decl


def _generate_failure_flag_check_in_main_func_switch_case(flag_ref, func, info):
    """
    Generate checks after calling a function (@param func) that may fail from
    the BPF main function. This function generates a Switch-Case on the value
    of failure_number.
    @param flag_ref: the reference to the failure number variable
    @param func:     the func that was called and may fail.
    @param info:
    @returns: Instruction
    """
    # We must be in BPF main function
    current_function = None

    decl = []

    switch      = ControlFlowInst()
    switch.kind = clang.CursorKind.SWITCH_STMT
    switch.cond.add_inst(flag_ref)

    break_inst = Instruction()
    break_inst.kind = clang.CursorKind.BREAK_STMT
    case = CaseSTMT(None)
    case.case.add_inst(ZERO)
    case.body.add_inst(break_inst)
    switch.body.add_inst(case)

    for failure_number in set(func.path_ids):
        assert failure_number != 0, 'The zero can not be a failure id'
        # TODO: change declaration to a dictionary instead of array
        meta = info.user_prog.declarations[failure_number-1]
        prepare_meta_code, tmp_decl = prepare_meta_data(failure_number, meta, info)
        decl.extend(tmp_decl)

        # Check the failure number
        int_literal = Literal(str(failure_number), clang.CursorKind.INTEGER_LITERAL)
        case        = CaseSTMT(None)
        case.case.add_inst(int_literal)
        case.body.extend_inst(prepare_meta_code)
        case.body.add_inst(ToUserspace.from_func_obj(current_function))
        switch.body.add_inst(case)
    return switch, decl


def _handle_function_may_fail(inst, func, info, more):
    ctx = more.ctx

    blk = cb_ref.get(BODY)

    before_func_call = []
    after_func_call = []

    if func.may_succeed:
        ## we need to pass a flag

        if inst.change_applied & Function.FAIL_FLAG != 0:
            # Nothing to do
            return inst
        inst.change_applied |= Function.FAIL_FLAG

        assert (func.change_applied & Function.FAIL_FLAG) != 0, f'The fail flag should alread be added to the function definition (func:{func.name})'

        # Pass the flag when invoking the function
        # First check if we need to allocate the flag on the stack memory
        sym = info.sym_tbl.lookup(FAIL_FLAG_NAME)
        is_defined = sym is not None
        # debug('on func:', current_function.name if current_function else 'MAIN', ' and the fail flag is defined on stack[T/F]?:', is_on_the_stack)
        if not is_defined:
            _decl_failure_flag_on_stack(info)
            sym = info.sym_tbl.lookup(FAIL_FLAG_NAME)
        assert sym is not None, 'By now the flag should be defined'

        is_flag_pointer = sym.type.is_pointer()

        # Now add the argument to the invocation instruction
        # TODO: update every invocation of this function with the flag parameter
        flag_ref = Ref.from_sym(sym)
        if is_flag_pointer:
            inst.args.append(flag_ref)
        else:
            addr_op = UnaryOp.build('&', flag_ref)
            inst.args.append(addr_op)

        tmp = Literal('/* check if function fail */\n', CODE_LITERAL)
        after_func_call.append(tmp)

        # How should we return to from this function?
        return_stmt = ToUserspace.from_func_obj(current_function)

        if current_function == None:
            assert len(func.path_ids) > 0
            return_stmt, tmp_decl = _generate_failure_flag_check_in_main_func_switch_case(flag_ref, func, info)
            declare_at_top_of_func.extend(tmp_decl)

        # The code that should run when there is a failure
        if flag_ref.type.is_pointer():
            flag_val = UnaryOp.build('*', flag_ref)
        else:
            flag_val = flag_ref
        # cond = BinOp.build(flag_val, '!=', ZERO)
        # if_inst = ControlFlowInst.build_if_inst(cond)
        # if_inst.body.add_inst(return_stmt)
        # after_func_call.append(if_inst)
        after_func_call.append(return_stmt)

        # Analyse the called function.
        if func.name not in _has_processed:
            _has_processed.add(func.name)
            with remember_func(func):
                with info.sym_tbl.with_func_scope(func.name):
                    with _new_top_func_declare_context():
                        body = _do_pass(func.body, info, PassObject())
                        body.children = declare_at_top_of_func + body.children
                        func.body = body
    else:
        # The callee function is going to fail
        if current_function and current_function.may_succeed:
            # We need to notify the caller
            # TODO: what failure path should we notify?
            error("It seems there is bug here. We are not notifying the failure number")
            sym = info.sym_tbl.lookup(FAIL_FLAG_NAME)
            assert sym is not None, 'if it is not defined, then probably we should define it here'
            bin_op = _set_failure_flag(1, sym.type.is_pointer())
            after_func_call.append(bin_op)
            after_func_call.append(ToUserspace.from_func_obj(current_function))
        else:
            # The caller knows we are going to fail (this function never
            # succeed)
            # The next check is just for debugging
            if current_function:
                assert (current_function.may_fail and not
                        current_function.may_succeed)

            if not current_function:
                # We are in the main BPF function, we should fallback t user
                error("It seems there is bug here. We are not notifying the failure number")
                after_func_call.append(ToUserspace.from_func_obj(current_function))


        # Also take a look at the body of the called function. We may want to
        # remove everything after failure point.
        if func.name not in _has_processed:
            _has_processed.add(func.name)
            with remember_func(func):
                with info.sym_tbl.with_func_scope(func.name):
                    with _new_top_func_declare_context():
                        body = _do_pass(func.body, info, PassObject())
                        body.children = declare_at_top_of_func + body.children
                        func.body = body

    blk.extend(before_func_call)
    blk.append(After(after_func_call))
    return inst


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        func = inst.get_function_def()
        # we only need to investigate functions that may fail
        if func and not func.is_empty() and func.may_fail:
            return _handle_function_may_fail(inst, func, info, more)
    elif inst.kind == TO_USERSPACE_INST:
        blk = cb_ref.get(BODY)
        failure_number = inst.path_id
        if current_function is None:
            # Found a split point on the BPF entry function
            meta = info.user_prog.declarations[failure_number - 1]
            prepare_pkt, tmp_decl = prepare_meta_data(failure_number, meta, info)
            declare_at_top_of_func.extend(tmp_decl)
            blk.extend(prepare_pkt)
        else:
            sym = info.sym_tbl.lookup(FAIL_FLAG_NAME)
            if sym is None:
                _decl_failure_flag_on_stack(info)
                sym = info.sym_tbl.lookup(FAIL_FLAG_NAME)
            assert sym is not None, 'We want to set the failure flag, it should be already defined!'
            set_failuer = _set_failure_flag(failure_number, sym.type.is_pointer())
            blk.append(set_failuer)
    return inst


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
    new_children = []

    with cb_ref.new_ref(ctx, parent_list):
        # Process current instruction
        inst = _process_current_inst(inst, info, more)
        if inst is None:
            debug(MODULE_TAG, 'remove instruction:', inst)
            return None

        # Continue deeper
        for child, tag in inst.get_children_context_marked():
            if isinstance(child, list):
                new_child = []
                for i in child:
                    obj = PassObject.pack(lvl+1, tag, new_child)
                    new_inst = _do_pass(i, info, obj)
                    if new_inst is None:
                        if inst.tag == BODY:
                            debug(MODULE_TAG, 'remove instruction from body:', inst)
                            continue
                        else:
                            debug(MODULE_TAG, 'remove instruction:', inst)
                            return None

                    after = []
                    while new_child and isinstance(new_child[-1], After):
                        after.append(new_child.pop())
                    new_child.append(new_inst)
                    for a in reversed(after):
                        new_child.extend(a.box)

                    if i.kind == TO_USERSPACE_INST:
                        # debug(MODULE_TAG, 'Found to Userspace trim the code')
                        break
            else:
                obj = PassObject.pack(lvl+1, tag, parent_list)
                new_child = _do_pass(child, info, obj)
                if new_child is None:
                    debug(MODULE_TAG, 'remove instruction:', inst)
                    return None
            new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def userspace_fallback_pass(inst, info, more):
    with remember_func(None):
        with _new_top_func_declare_context():
            body = _do_pass(inst, info, more)
            body.children = declare_at_top_of_func + body.children
    return body
