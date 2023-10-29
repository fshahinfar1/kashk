import itertools
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from template import bpf_ctx_bound_check, bpf_ctx_bound_check_bytes
from prune import KNOWN_FUNCS, OUR_IMPLEMENTED_FUNC

from helpers.bpf_ctx_helper import (is_bpf_ctx_ptr, is_value_from_bpf_ctx,
        set_ref_bpf_ctx_state)


MODULE_TAG = '[Verfier Pass]'
# TODO:The CodeBlockRef thing is not correct and works really bad. Find a way
# to fix it.
cb_ref = CodeBlockRef()
_has_processed_func = set()


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
    for x in [lhs, rhs]:
        # TODO: this API is awful
        R = []
        if is_value_from_bpf_ctx(x, info, R):
            ref, index, T = R.pop()
            assert isinstance(ref, Instruction)
            assert isinstance(index, Instruction)

            # TODO: this definition is duplicated through this file! do something better
            skb_ref = Ref(None)
            skb_ref.name = info.prog.ctx
            skb_ref.kind = clang.CursorKind.DECL_REF_EXPR
            skb_ref.type = BASE_TYPES[SKB_PTR_TYPE]

            # (__u64)skb->data_end
            end_ref = Ref(None, kind=clang.CursorKind.MEMBER_REF_EXPR)
            end_ref.name = 'data_end'
            end_ref.owner.append(skb_ref)
            end_ref.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
            data_end = Cast()
            data_end.cast_type = '__u64'
            data_end.castee.add_inst(end_ref)
            check_inst = bpf_ctx_bound_check(ref, index, data_end)

            tmp,_ = gen_code([inst], info)
            report(f'Add a bound check before:\n    {tmp}')
            debug(x, x.kind)

            blk = cb_ref.get(BODY)
            # Add the check a line before this access
            blk.append(check_inst)
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
            print('***', size, size.kind)

            # Add the check a line before this access
            skb_ref = Ref(None)
            skb_ref.name = info.prog.ctx
            skb_ref.kind = clang.CursorKind.DECL_REF_EXPR
            skb_ref.type = BASE_TYPES[SKB_PTR_TYPE]

            end_ref = Ref(None, kind=clang.CursorKind.MEMBER_REF_EXPR)
            end_ref.name = 'data_end'
            end_ref.owner.append(skb_ref)
            data_end = Cast()
            data_end.cast_type = '__u64'
            data_end.castee.add_inst(end_ref)
            check_inst = bpf_ctx_bound_check_bytes(ref, size, data_end)

            blk = cb_ref.get(BODY)
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
    return _do_pass(inst, info, more)
