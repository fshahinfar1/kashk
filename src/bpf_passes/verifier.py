import itertools
from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *
from utility import get_tmp_var_name, show_insts

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from template import bpf_ctx_bound_check, bpf_ctx_bound_check_bytes
from prune import KNOWN_FUNCS, OUR_IMPLEMENTED_FUNC

from helpers.bpf_ctx_helper import (is_bpf_ctx_ptr, is_value_from_bpf_ctx,
        set_ref_bpf_ctx_state)
from helpers.instruction_helper import get_ret_inst, is_variable, get_scalar_variables


MODULE_TAG = '[Verfier Pass]'
# TODO:The CodeBlockRef thing is not correct and works really bad. Find a way
# to fix it.
cb_ref = CodeBlockRef()
_has_processed_func = set()
current_function = None
declare_at_top_of_func = None


@contextmanager
def set_current_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield func
    finally:
        current_function = tmp


def _check_if_variable_index_should_be_masked(ref, index, blk, info):
    """
    The ref, index are taken from range (R) list used for checking access to
    the BPF context. blk is the current block of code to add the masking operation to.
    """
    set_of_variables_to_be_masked = get_scalar_variables(ref) + get_scalar_variables(index)
    # print('these are scalar variables:', set_of_variables_to_be_masked)
    for var in  set_of_variables_to_be_masked:
        # TODO: should I keep the variable in tack and define a tmp value for masking? Then I should replace the access instruction and use the masked variables.
        # decl_index  = VarDecl.build(get_tmp_var_name(), index.type)
        # declare_at_top_of_func.append(decl_index)
        # ref_index   = decl_index.get_ref()

        mask_op     = BinOp.build_op(var, '&', info.prog.index_mask)
        # mask_assign = BinOp.build_op(ref_index, '=', mask_op)
        mask_assign = BinOp.build_op(var, '=', mask_op)
        # index = ref_index.clone([])
        blk.append(mask_assign)


def _handle_binop(inst, info, more):
    lhs = inst.lhs.children[0]
    rhs = inst.rhs.children[0]
    # Track which variables are pointer to the BPF context
    if inst.op == '=':
        # lhs_is_ptr = is_bpf_ctx_ptr(lhs, info)
        rhs_is_ptr = is_bpf_ctx_ptr(rhs, info)
        # debug("***", gen_code([inst,], info), '|| LHS kind:', lhs.kind, '|| RHS kind:', rhs.kind, '|| is rhs ctx:', rhs_is_ptr)
        set_ref_bpf_ctx_state(lhs, rhs_is_ptr, info)
        # assert is_bpf_ctx_ptr(lhs, info) == rhs_is_ptr, 'Check if set_ref_bpf_ctx_state and is_bpf_ctx_ptr work correctly'
        if is_bpf_ctx_ptr(lhs, info) != rhs_is_ptr:
            error(MODULE_TAG, 'Failed to set the BPF context flag on reference', lhs)

    # Check if the BPF context is accessed and add bound checking
    blk = cb_ref.get(BODY)
    for x in [lhs, rhs]:
        # TODO: this API is awful
        R = []
        if is_value_from_bpf_ctx(x, info, R):
            ref, index, T = R.pop()
            assert isinstance(ref, Instruction)
            assert isinstance(index, Instruction)

            _check_if_variable_index_should_be_masked(inst, index, blk, info)

            ctx_ref = info.prog.get_ctx_ref()
            end_ref = ctx_ref.get_ref_field('data_end', info)
            data_end = Cast.build(end_ref, BASE_TYPES[clang.TypeKind.ULONGLONG])
            _ret_inst = get_ret_inst(current_function, info).body[0]
            check_inst = bpf_ctx_bound_check(ref, index, data_end, _ret_inst)
            blk.append(check_inst)

            # Report for debuging
            tmp,_ = gen_code([inst], info)
            debug(f'Add a bound check before:\n    {tmp}')
    # Keep the instruction unchanged
    return inst


def _handle_call(inst, info, more):
    # Are we passing BPF context pointer to the function?
    # If yest, find the position of the argument.
    pos_of_ctx_ptrs = []
    for pos, a in enumerate(inst.args):
        if is_bpf_ctx_ptr(a, info):
            pos_of_ctx_ptrs.append(pos)

    if not pos_of_ctx_ptrs:
        # We are not passing any special pointers. We do not need to
        # investigate inside of the function.
        return inst

    # Find the definition of the function and step into it
    func = inst.get_function_def()
    if func and not func.is_empty() and func.name not in OUR_IMPLEMENTED_FUNC:
        with info.sym_tbl.with_func_scope(inst.name):
            # Add skb as the last parameter of this function
            if func.change_applied & Function.CTX_FLAG == 0:
                skb_obj = StateObject(None)
                skb_obj.name = info.prog.ctx
                skb_obj.type_ref = info.prog.ctx_type
                func.args.append(skb_obj)
                func.change_applied |= Function.CTX_FLAG

                # This is added to the scope of function being called
                info.sym_tbl.insert_entry(skb_obj.name, info.prog.ctx_type,
                        clang.CursorKind.PARM_DECL, None)

            if inst.change_applied & Function.CTX_FLAG == 0:
                # TODO: update every invocation of this function with the skb parameter
                # TODO: what if the caller function does not have access to skb?
                skb_ref = Ref(None, kind=clang.CursorKind.DECL_REF_EXPR)
                skb_ref.name = info.prog.ctx
                skb_ref.type = info.prog.ctx_type
                inst.args.append(skb_ref)
                inst.change_applied |= Function.CTX_FLAG

            for pos in pos_of_ctx_ptrs:
                param = func.args[pos]
                sym = info.sym_tbl.lookup(param.name)
                sym.is_bpf_ctx = True
                # debug('function:', inst.name, 'param:', param.name, 'is bpf ctx')
                # TODO: do I need to turn the flag off when removing
                # the scope of the function? (maybe in another run the
                # parameter is not a pointer to the context)

            # Check to not repeat analyzing same function multiple times.
            if inst.name not in _has_processed_func:
                with set_current_func(func):
                    modified = _do_pass(func.body, info, PassObject())
                assert modified is not None
                # Update the instructions of the function
                func.body = modified
    else:
        if inst.name not in KNOWN_FUNCS + OUR_IMPLEMENTED_FUNC:
            # We can not modify this function
            error(MODULE_TAG, 'function:', inst.name,
                'receives BPF context but is not accessible for modification')
        else:
            ref = inst.args[0]
            size = inst.args[2]

            blk = cb_ref.get(BODY)
            _check_if_variable_index_should_be_masked(ref, size, blk, info)

            # Add the check a line before this access
            ctx_ref = info.prog.get_ctx_ref()
            end_ref = ctx_ref.get_ref_field('data_end', info)
            data_end = Cast.build(end_ref, BASE_TYPES[clang.TypeKind.ULONGLONG])
            _ret_inst = get_ret_inst(current_function, info).body[0]
            check_inst = bpf_ctx_bound_check_bytes(ref, size, data_end, _ret_inst)

            blk.append(check_inst)
    return inst


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.BINARY_OPERATOR:
        return _handle_binop(inst, info, more)
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        return _handle_call(inst, info, more)
    # Ignore other instructions
    return inst


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
    new_children = []

    with cb_ref.new_ref(ctx, parent_list):
        # Process current instruction
        inst = _process_current_inst(inst, info, more)

        if inst is None:
            # This instruction should be removed
            return None

        # Continue deeper
        for child, tag in inst.get_children_context_marked():
            if isinstance(child, list):
                new_child = []
                for i in child:
                    obj = PassObject.pack(lvl+1, tag, new_child)
                    new_inst = _do_pass(i, info, obj)
                    if new_inst is not None:
                        new_child.append(new_inst)
            else:
                obj = PassObject.pack(lvl+1, tag, parent_list)
                new_child = _do_pass(child, info, obj)
                assert new_child is not None, 'It seems this pass does not need to remove any instruction. Just checking.'
            new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def verifier_pass(inst, info, more):
    # TODO: There is an issue, in the futuer pass that rely on the condition of
    # the varibale being from the BPF context or not (2nd transform) the
    # variable might only be from the BPF context in a part of the code.
    # I need to the keep track of when the variable is BPF context not just
    # which.
    """
    This pass performs following operations
    1. Marks variables that have value from BPF context
    2. Adds bound checking. The bound checking is added when a value from BPF
    context is accessed. It happens when passing the value to a function or
    when it is used in with an operator.
    """
    declare_at_top_of_func = []
    with set_current_func(None):
        return _do_pass(inst, info, more)
