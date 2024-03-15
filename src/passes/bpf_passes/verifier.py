import itertools
from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *
from my_type import MyType
from utility import get_tmp_var_name, skip_typedef

from code_gen import gen_code
from passes.pass_obj import PassObject
from template import bpf_ctx_bound_check, bpf_ctx_bound_check_bytes
from prune import WRITE_PACKET, KNOWN_FUNCS, OUR_IMPLEMENTED_FUNC, MEMORY_ACCESS_FUNC

from helpers.bpf_ctx_helper import (is_bpf_ctx_ptr, is_value_from_bpf_ctx,
        set_ref_bpf_ctx_state)
from helpers.instruction_helper import (get_ret_inst, get_scalar_variables,
        get_ret_value_text, get_ref_symbol, add_flag_to_func,
        simplify_inst_to_ref, ZERO)
from sym_table import MemoryRegion
from passes.update_original_ref import set_original_ref


MODULE_TAG = '[Verfier Pass]'
# TODO:The CodeBlockRef thing is not correct and works really bad. Find a way
# to fix it.
cb_ref = CodeBlockRef()
_has_processed_func = set()
current_function = None
backward_jmp_ctx = None


@contextmanager
def set_current_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield func
    finally:
        current_function = tmp


@contextmanager
def new_backward_jump_context(off=False):
    """
    @off: disable backward jump context
    """
    global backward_jmp_ctx
    tmp = backward_jmp_ctx

    if off:
        backward_jmp_ctx = None
    else:
        backward_jmp_ctx = []

    try:
        yield backward_jmp_ctx
    finally:
        backward_jmp_ctx = tmp


# class BoundCheckState:
#     MODE_BYTES   = 100
#     MODE_INDEXES = 200

#     def __init__(self):
#         self.mode = 0
#         self.ref = None
#         self.index = None

#     def can_merge(self, other):
#         if self.mode != other.mode:
#             return False
#         if (self.ref.name != other.ref.name):
#             return False
#         if (self.index.kind != clang.CursorKind.INTEGER_LITERAL or
#                 other.index.kind != clang.CursorKind.INTEGER_LITERAL):
#             return False
#         return True

#     def __str__(self):
#         return f'MODE: {self.mode}   REF: {self.ref}   INDEX: {self.index}'


def _check_if_variable_index_should_be_masked(ref, index, blk, info):
    """
    The ref, index are taken from range (R) list used for checking access to
    the BPF context. blk is the current block of code to add the masking operation to.
    """
    set_of_variables_to_be_masked = get_scalar_variables(ref) + get_scalar_variables(index)
    # debug('these are scalar variables:', set_of_variables_to_be_masked, tag=MODULE_TAG)
    for var in set_of_variables_to_be_masked:
        # TODO: should I keep the variable intact and define a tmp value for
        # masking? Then I should replace the access instruction and use the
        # masked variables.

        sym = get_ref_symbol(var, info)
        if sym is None:
            error('Failed to find symbol!')
            debug(MODULE_TAG, var, tag=MODULE_TAG)
            debug(info.sym_tbl.current_scope.symbols, tag=MODULE_TAG)
            raise Exception('Failure')
        if sym.is_bpf_ctx:
            continue
        mask_op     = BinOp.build(var, '&', info.prog.index_mask)
        mask_assign = BinOp.build(var, '=', mask_op)
        mask_assign.set_modified(InstructionColor.EXTRA_ALU_OP)
        blk.append(mask_assign)
        set_original_ref(mask_assign, info, ref.original)


def _do_add_bound_check(blk, R, current_function, info, bytes_mode):
    ref, index, size = R
    data_end = info.prog.get_pkt_end()
    tmp = get_ret_inst(current_function, info)
    if tmp.body.has_children():
        _ret_inst = tmp.body.children[0]
    else:
        _ret_inst = None
    if bytes_mode:
        check_inst = bpf_ctx_bound_check_bytes(ref, index, data_end, current_function)
    else:
        check_inst = bpf_ctx_bound_check(ref, index, data_end, current_function)
    blk.append(check_inst)
    # if current_function is not None:
    #     # The bound check may fail and the function may fail as a result
    #     current_function.may_fail = True
    #     n = '[[main]]' if current_function is None else current_function.name
    #     print('here @', n,  current_function.may_fail, current_function.may_succeed)
    set_original_ref(check_inst, info, ref.original)
    ref.set_flag(Instruction.BOUND_CHECK_FLAG)


def _add_bound_check(blk, R, current_function, info, bytes_mode, more):
    _do_add_bound_check(blk, R, current_function, info, bytes_mode)
    # ref, index, size = R

    # lst = more.last_bound_check

    # check = BoundCheckState()
    # check.mode = BoundCheckState.MODE_BYTES if bytes_mode else BoundCheckState.MODE_INDEXES
    # check.ref = ref
    # check.index = index

    # debug('Adding bound check. previous check:', lst, tag=MODULE_TAG)
    # debug('New bound check:', check, tag=MODULE_TAG)
    # if lst is None:
    #     debug('can merge?: No', tag=MODULE_TAG)
    # else:
    #     debug('can merge?:', lst.can_merge(check), tag=MODULE_TAG)

    # if (lst is None or lst.can_merge(check)):
    #     # Update/Merge the bound checks
    #     more.last_bound_check = check
    #     debug('have to decide which bound check to keep', tag=MODULE_TAG)
    # else:
    #     # Can not merge!
    #     # create the previous bound check and pospone the last bound check for
    #     # later.
    #     r = (lst.ref, lst.index, None)
    #     _do_add_bound_check(blk, r, current_function, info, bytes_mode)
    #     more.last_bound_check = check


def _track_bpf_ctx_pointer_propagation(inst, info, more):
    assert isinstance(inst, BinOp)
    # Track which variables are pointer to the BPF context
    if inst.op != '=':
        return
    lhs = inst.lhs.children[0]
    rhs = inst.rhs.children[0]
    T = lhs.type
    # Check if we are assigning a reference
    if not T.is_pointer() and not T.is_array():
        return
    rhs_is_ptr = is_bpf_ctx_ptr(rhs, info)
    # debug("***", gen_code([inst,], info)[0], '|| LHS kind:', lhs.kind, '|| RHS kind:', rhs.kind, '|| is rhs ctx:', rhs_is_ptr, tag=MODULE_TAG)
    set_ref_bpf_ctx_state(lhs, rhs_is_ptr, info)
    # assert is_bpf_ctx_ptr(lhs, info) == rhs_is_ptr, 'Check if set_ref_bpf_ctx_state and is_bpf_ctx_ptr work correctly'
    if is_bpf_ctx_ptr(lhs, info) != rhs_is_ptr:
        error(MODULE_TAG,
                'Failed to set the BPF context flag on reference', lhs)
    if backward_jmp_ctx is not None and rhs_is_ptr:
        backward_jmp_ctx.append(lhs)


def _handle_binop(inst, info, more):
    lhs = inst.lhs.children[0]
    rhs = inst.rhs.children[0]
    _track_bpf_ctx_pointer_propagation(inst, info, more)
    # Check if the BPF context is accessed and add bound checking
    blk = cb_ref.get(BODY)
    for x in [lhs, rhs]:
        # TODO: this API is awful
        R = []
        if is_value_from_bpf_ctx(x, info, R):
            r = R.pop()
            ref, index, T = r
            if ref.has_flag(Instruction.BOUND_CHECK_FLAG):
                continue

            assert isinstance(ref, Instruction)
            assert isinstance(index, Instruction)

            _check_if_variable_index_should_be_masked(ref, index, blk, info)
            # debug('add bound check because binary operator access packet' , tag=MODULE_TAG)
            _add_bound_check(blk, r, current_function, info, bytes_mode=False, more=more)

            # Report for debuging
            tmp,_ = gen_code([inst], info)
            debug(f'Add a bound check before:\n    {tmp}', tag=MODULE_TAG)
    # Keep the instruction unchanged
    return inst


class FoundFields:
    def __init__(self):
        self.count_bpf_fields = 0
        self.fields = []


def _has_bpf_ctx_in_field(ref, info, field_name=None):
    assert isinstance(ref, Instruction)
    found = False
    T = ref.type
    T = get_actual_type(T)
    if T.is_record():
        name = T.spelling[len('struct '):]
        decl = MyType.type_table.get(name)
        if not decl:
            error(f'Did not found the definition of the Record {T.spelling}')
            return False

        # First check if any of the fields are BPF context
        for field in decl.fields:
            ref_field = Ref.build(field.name, field.type_ref, is_member=True)
            ref_field.owner = [ref,]
            if hasattr(ref, 'owner'):
                ref_field.owner +=  ref.owner
            if is_bpf_ctx_ptr(ref_field, info):
                if field_name is not None:
                    field_name.fields.append([ref_field,])
                    found = True
                    field_name.count_bpf_fields += 1
                    debug(ref, field.name, 'is BPF CTX', tag=MODULE_TAG)
            else:
                debug('The field is not BPF', ref_field, tag=MODULE_TAG)
                pass

        # Check if any of the field has an object which is BPF context
        # for field in decl.fields:
        #     if _has_bpf_ctx_in_field(field, info, field_name):
        #         return True
        # TODO: it might have a field of the type from the parent class. There
        # would be a recursion here which I might not be able to solve.
    return found


def _check_passing_bpf_context(inst, func, info):
    callee_scope = info.sym_tbl.scope_mapping[func.name]
    receives_bpf_ctx = False

    # Find BPF pointers passed to a function
    for pos, a in enumerate(inst.args):
        param = func.args[pos]
        if is_bpf_ctx_ptr(a, info):
            # First check if the argument it self is a pointer to BPF ctx
            text = gen_code(a, info)[0]
            debug(f'func: {func.name} | Passing BPF_CTX as argument {param.name} <-- {text}', tag=MODULE_TAG)
            sym = callee_scope.lookup(param.name)
            sym.set_is_bpf_ctx(True)
            receives_bpf_ctx = True
        else:
            # Otherwise, check if the argument has a field, which is a pointer
            # to BPF context
            if not hasattr(a, 'type') and not isinstance(a, Literal):
                error('do not know the type for', a, a.kind)
                continue
            if not (a.type.is_pointer() or a.type.is_array()):
                # We are not passing a reference. Passing a value copies data.
                # So it is not the BPF context anymore.
                continue

            # check if the argument is a record or not
            # (Not record --> Not composit type --> no BPF_CTX field)
            # [ignore pointers, get the underlying type]
            T = get_actual_type(a.type)
            if not T.is_record():
                continue

            # I am not handling typecasting!
            # NOTE: if we figure that this argument is a BPF context,
            # then we will want to mark the parameter in the function scope as
            # receiving a BPF context pointer. But when there is a typecase, I
            # will not understand which field of the parameter object is
            # receiving the pointer (we are checking the compound data
            # structure here).
            _tmp = get_actual_type(param.type_ref)
            if _tmp.spelling != T.spelling:
                error('There is a type cast when passing the argument. I lose track of BPF context when there is a type cast! [1]')
                debug(f'param: {_tmp.spelling}    argument: {T.spelling}', tag=MODULE_TAG)
                continue

            # if not isinstance(a, Ref):
            #     debug('I am not checking whether the argument which are not simple references (e.g, are operations) have BPF context as a field or not', tag=MODULE_TAG)
            #     debug('debug info:', tag=MODULE_TAG)
            #     text, _ = gen_code([a,], info)
            #     debug(a, tag=MODULE_TAG)
            #     debug(text, tag=MODULE_TAG)
            #     debug('--------', tag=MODULE_TAG)
            #     continue

            fields = FoundFields()
            # debug(callee_scope.symbols, tag=MODULE_TAG)
            if _has_bpf_ctx_in_field(a, info, fields):
                text, _ = gen_code([a, ], info)
                debug('Has bpf context in the field:', a, '|', text, tag=MODULE_TAG)
                param_sym = callee_scope.lookup(param.name)
                assert param_sym is not None, 'We should have all the parameters in the scope of functions'
                # debug('fields:', field, tag=MODULE_TAG)
                for field in fields.fields:
                    scope = param_sym.fields
                    for ref in reversed(field):
                        sym = scope.lookup(ref.name)
                        if sym is None:
                                sym = scope.insert_entry(ref.name, ref.type, clang.CursorKind.MEMBER_REF_EXPR, None)
                        scope = sym.fields
                    sym.set_is_bpf_ctx(True)
                    receives_bpf_ctx = True
                    # debug(f'Set the {param.name} .. {sym.name} to BPF_CTX', tag=MODULE_TAG)
            else:
                text, _ = gen_code([a, ], info)
                debug(f'Does not have BPF CTX in its field', a, '|', text, tag=MODULE_TAG)
                pass
    return receives_bpf_ctx


def _check_setting_bpf_context_in_callee(inst, func, info):
    debug('checking func:', inst.name, tag=MODULE_TAG)
    callee_scope = info.sym_tbl.scope_mapping[func.name]

    # Check if value of pointers passed to this function was changed to point
    # to BPF context
    # NOTE: it is important that this code be in the context of caller function
    for param, argum in zip(func.get_arguments(), inst.get_arguments()):
        # TODO: do I need to skip typedef to get to the udner type ?
        # get_typedef_under(param.type_ref)
        if not param.type_ref.is_pointer() and not param.type_ref.is_array():
            # Only pointer and arrays can carry the BPF context to this scope
            continue

        ref = argum
        if not isinstance(ref, Ref):
            tmp = simplify_inst_to_ref(ref)
            if tmp is None:
                # TODO: I have not implemented the other cases.
                # A question, How complex can it get?
                continue
            ref = tmp

        debug(f'Parameter {param.name} ({param.type_ref.kind}) is given argument {ref.owner} {ref.name} ({ref.type})', tag=MODULE_TAG)

        # If the pointer it self is set to be BPF context, then the pointer
        # will be BPF context in this scope too.
        param_sym = callee_scope.lookup(param.name)
        assert param_sym is not None, f'The function parameters should be found in its symbol table\'s scope ({param.name})'
        argum_sym = get_ref_symbol(ref, info)
        if argum_sym is None:
            error(MODULE_TAG, '(Checking BPF_CTX set in callee)',
                    'Did not found the symbol for argument', ref)
            continue

        if param_sym.is_bpf_ctx:
            argum_sym.set_is_bpf_ctx(True)
            # report(ref.owner, ref.name, 'is bpf context')

            if backward_jmp_ctx:
                # TODO: check if this should be argum or ref
                backward_jmp_ctx.append(argum)

        one_type_is_record = (param.type_ref.under_type.is_record() or
                argum.type.under_type.is_record())
        _tmp1 = get_actual_type(param.type)
        _tmp2 = get_actual_type(argum.type)
        if (one_type_is_record and _tmp1.spelling != _tmp2.spelling):
            error('There is a type cast when passing the argument. I lose track of BPF context when there is a type cast!')
            debug('argument type:', _tmp1.spelling, 'parameter type:',
                    _tmp2.spelling)
            continue

        if param.type_ref.is_pointer():
            ptr_type = param.type_ref.get_pointee()
            ptr_type = skip_typedef(ptr_type)
            # NOTE: If the pointer is to a structure, then check if each field
            # of that pointer is set to BPF.  Recursion here!
            if ptr_type.is_record():
                for key, entry in param_sym.fields.symbols.items():
                    # propagate the state of being BPF context or not from the
                    # callee scope to caller scope
                    e2 = argum_sym.fields.lookup(key)
                    if e2 is None:
                        e2 = argum_sym.fields.insert_entry(entry.name, entry.type, entry.kind, None)
                    e2.set_is_bpf_ctx(entry.is_bpf_ctx)
                    # report(argum.name, e2.name, 'is bpf ctx:', entry.is_bpf_ctx)
                    if backward_jmp_ctx and e2.is_bpf_ctx:
                        field = argum.get_ref_field(key, info)
                        backward_jmp_ctx.append(field)


def _pass_ctx_to_func_if_needed(inst, func, info):
    if func.change_applied & Function.CTX_FLAG == 0:
        add_flag_to_func(Function.CTX_FLAG, func, info)
        # TODO: I need to go through the code and the context to the all of the
        # instructions invoking this function.
    if inst.change_applied & Function.CTX_FLAG == 0:
        inst.change_applied |= Function.CTX_FLAG
        inst.args.append(info.prog.get_ctx_ref())


def _step_into_func_and_track_context(inst, func, info):
    receives_bpf_ctx = _check_passing_bpf_context(inst, func, info)
    if receives_bpf_ctx:
        _pass_ctx_to_func_if_needed(inst, func, info)
    # Check to not repeat analyzing same function multiple times.
    # TODO: buf what if the inputs are different in (terms of being bpf context)?
    # if inst.name not in _has_processed_func:
    #     _has_processed_func.add(inst.name)
    with new_backward_jump_context(off=True):
        with info.sym_tbl.with_func_scope(inst.name):
            with set_current_func(func):
                obj = PassObject()
                obj.last_bound_check = None
                func.body = _do_pass(func.body, info, obj)

    _check_setting_bpf_context_in_callee(inst, func, info)


def _handle_call(inst, info, more):
    # Find the definition of the function and step into it
    func = inst.get_function_def()
    if func and not func.is_empty() and func.name not in OUR_IMPLEMENTED_FUNC:
        _step_into_func_and_track_context(inst, func, info)
    else:
        # Check if there is argument which is BPF context
        for a in inst.args:
            if is_bpf_ctx_ptr(a, info):
                break
        else:
            # There is none
            return inst

        if inst.name in ('memcpy', 'memmove', 'strcpy', 'strncpy',):
            # TODO: this is handing memcpy, handle other known fucntions
            ref = inst.args[0]
            size = inst.args[2]
            if ref.has_flag(Instruction.BOUND_CHECK_FLAG):
                return inst
            blk = cb_ref.get(BODY)
            # text, _ = gen_code(blk, info)
            # debug(text, tag=MODULE_TAG)
            # text, _ = gen_code([inst,], info)
            # debug(text, tag=MODULE_TAG)
            _check_if_variable_index_should_be_masked(ref, size, blk, info)
            # Add the check a line before this access
            debug('add bound check because calling known function accessing packet' , tag=MODULE_TAG)
            _add_bound_check(blk, (ref, size, ZERO), current_function, info, bytes_mode=True, more=more)
        elif inst.name not in itertools.chain(OUR_IMPLEMENTED_FUNC, WRITE_PACKET):
            # We can not modify this function
            error(MODULE_TAG, 'function:', inst.name,
                'receives BPF context but is not accessible for modification')
        else:
            debug('<><><>', inst.name, 'I only considered some functions, also check for other mem access functions', tag=MODULE_TAG)
            pass
    return inst


def _handle_array_access(inst, info, more):
    assert isinstance(inst, ArrayAccess)
    if inst.has_flag(Instruction.BOUND_CHECK_FLAG):
        # Has processed it before
        return inst
    tmp_name = inst.name
    if tmp_name is None:
        error('Did not found the name for bound checking the array', tag=MODULE_TAG)
        return inst
    sym = info.sym_tbl.lookup(tmp_name)
    if sym is None:
        debug('Did not found symbol table for', inst, tag=MODULE_TAG)
        return inst

    if is_value_from_bpf_ctx(inst, info, None):
        debug('it is a buf dereference, we will check it later', tag=MODULE_TAG)
        return inst

    # debug(inst, sym.memory_region, '--->', sym.referencing_memory_region, tag=MODULE_TAG)
    # debug('---', inst, inst.array_ref, inst.array_ref.type)
    array_ref = inst.array_ref
    if array_ref.type.is_pointer():
        debug('Accessing pointer', array_ref, 'does it need bound checking?', tag=MODULE_TAG)
        return inst
    element_count = inst.array_ref.type.element_count
    # debug('doing bound check for array access:', inst, element_count)
    el_count = Literal(str(element_count), clang.CursorKind.INTEGER_LITERAL)

    index = inst.index.children[0]
    cond1 = BinOp.build(index, '>=', el_count)
    cond2 = BinOp.build(index, '<', ZERO)
    cond = BinOp.build(cond1, '||', cond2)
    check = ControlFlowInst.build_if_inst(cond)
    check.body.add_inst(ToUserspace.from_func_obj(current_function))
    check.likelihood = Likelihood.Unlikely
    blk = cb_ref.get(BODY)
    blk.append(check)
    set_original_ref(check, info, inst.original)
    check.set_modified(InstructionColor.CHECK)
    inst.set_flag(Instruction.BOUND_CHECK_FLAG)
    return inst


def _handle_unary_op(inst, info, more):
    assert isinstance(inst, UnaryOp)
    if inst.op != '*':
        return inst
    x = inst.operand
    R = []
    is_ctx = is_value_from_bpf_ctx(x, info, R)
    if not is_ctx:
        return inst
    r = R.pop()
    ref, index, size = r
    if ref.has_flag(Instruction.BOUND_CHECK_FLAG):
        return inst
    assert isinstance(ref, Instruction)
    assert isinstance(index, Instruction)
    _check_if_variable_index_should_be_masked(ref, index, blk, info)

    debug('add bound check because unary operator dereferences packet', tag=MODULE_TAG)
    _add_bound_check(blk, r, current_function, info, bytes_mode=False,
            more=more)
    # Report for debuging
    tmp,_ = gen_code([inst], info)
    debug(f'Add a bound check before:\n    {tmp}', tag=MODULE_TAG)
    return inst


def _handle_return(inst, info, more):
    if current_function is None:
        return inst
    count_children = len(inst.body.children)
    if count_children == 0:
        # void return
        return inst
    if count_children != 1:
        debug('Unexpected number of children for return instruction', tag=MODULE_TAG)
        debug('--', inst, inst.body.children, tag=MODULE_TAG)
        raise Exception('Unexpected number of children for return instruction')
    obj = inst.body.children[0]
    is_bpf_ptr = is_bpf_ctx_ptr(obj, info)
    if is_bpf_ptr:
        current_function.may_return_bpf_ctx_ptr = True
    return inst


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        return _handle_call(inst, info, more)
    elif inst.kind == clang.CursorKind.UNARY_OPERATOR:
        return _handle_unary_op(inst, info, more)
    elif inst.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        return _handle_array_access(inst, info, more)
    elif inst.kind == clang.CursorKind.RETURN_STMT:
        return _handle_return(inst, info, more)
    # Ignore other instructions
    return inst


def _end_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.BINARY_OPERATOR:
        return _handle_binop(inst, info, more)
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
        # ------------------------------------------------------------------
        # TODO: this backward jump implementation has a huge bug to be fixed.
        # In the first pass, I might add bound checks and these checks are lost
        # because this pass is only for infomation gathering. The checks are
        # not added in the second pass becasue the instructions are makred as
        # bound-checked.
        # I should fix this before uncommneting.
        # ------------------------------------------------------------------
        # if inst.kind in MAY_HAVE_BACKWARD_JUMP_INSTRUCTIONS:
        #     # This is a loop (may jump back), go through the loop once,
        #     # remember which fields my be BPF Context
        #     with new_backward_jump_context() as marked_refs:
        #         _do_pass(inst.body, info, PassObject())
        #         debug('in a loop these were marked:', tag=MODULE_TAG)
        #         tmp_sym = info.sym_tbl.lookup('head')
        #         if tmp_sym:
        #             debug('&&', tmp_sym.name, tmp_sym.is_bpf_ctx, tag=MODULE_TAG)
        #         for ref in marked_refs:
        #             debug('jump back mark', ref, tag=MODULE_TAG)
        #             set_ref_bpf_ctx_state(ref, True, info)
        #         debug('----------------------------', tag=MODULE_TAG)

        # Continue deeper
        for child, tag in inst.get_children_context_marked():
            if isinstance(child, list):
                new_child = []
                for i in child:
                    # TODO: The way the last bound check is passed and
                    # maintained is very bad!
                    obj = more.repack(lvl+1, tag, new_child)
                    new_inst = _do_pass(i, info, obj)
                    more.last_bound_check = obj.last_bound_check
                    if new_inst is not None:
                        new_child.append(new_inst)
            else:
                # TODO: The way the last bound check is passed and maintained
                # is very bad!
                obj = more.repack(lvl+1, tag, parent_list)
                new_child = _do_pass(child, info, obj)
                more.last_bound_check = obj.last_bound_check
                assert new_child is not None, 'It seems this pass does not need to remove any instruction. Just checking.'
            new_children.append(new_child)

        # These instructions are inside the `with cb.new_ref(...)`
        # This keeps the track of parent block of code (blk)
        new_inst = inst.clone(new_children)
        new_inst = _end_current_inst(new_inst, info, more)
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
    more.last_bound_check = None
    with set_current_func(None):
        return _do_pass(inst, info, more)
