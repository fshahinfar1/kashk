import itertools
from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *
from utility import get_tmp_var_name, skip_typedef

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from template import bpf_ctx_bound_check, bpf_ctx_bound_check_bytes
from prune import WRITE_PACKET, KNOWN_FUNCS, OUR_IMPLEMENTED_FUNC, MEMORY_ACCESS_FUNC

from helpers.bpf_ctx_helper import (is_bpf_ctx_ptr, is_value_from_bpf_ctx,
        set_ref_bpf_ctx_state)
from helpers.instruction_helper import get_ret_inst, get_scalar_variables, get_ret_value_text, get_ref_symbol, add_flag_to_func


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


def _check_if_variable_index_should_be_masked(ref, index, blk, info):
    """
    The ref, index are taken from range (R) list used for checking access to
    the BPF context. blk is the current block of code to add the masking operation to.
    """
    set_of_variables_to_be_masked = get_scalar_variables(ref) + get_scalar_variables(index)
    # debug('these are scalar variables:', set_of_variables_to_be_masked)
    for var in  set_of_variables_to_be_masked:
        # TODO: should I keep the variable intact and define a tmp value for
        # masking? Then I should replace the access instruction and use the
        # masked variables.

        sym = get_ref_symbol(var, info)
        if sym is None:
            error('Failed to find symbol!')
            debug(MODULE_TAG, var)
            debug(info.sym_tbl.current_scope.symbols)
            raise Exception('Failure')
        if sym.is_bpf_ctx:
            continue
        mask_op     = BinOp.build(var, '&', info.prog.index_mask)
        mask_assign = BinOp.build(var, '=', mask_op)
        blk.append(mask_assign)


def _handle_binop(inst, info, more):
    lhs = inst.lhs.children[0]
    rhs = inst.rhs.children[0]
    # Track which variables are pointer to the BPF context
    if inst.op == '=':
        rhs_is_ptr = is_bpf_ctx_ptr(rhs, info)
        # debug("***", gen_code([inst,], info), '|| LHS kind:', lhs.kind, '|| RHS kind:', rhs.kind, '|| is rhs ctx:', rhs_is_ptr)
        set_ref_bpf_ctx_state(lhs, rhs_is_ptr, info)
        # assert is_bpf_ctx_ptr(lhs, info) == rhs_is_ptr, 'Check if set_ref_bpf_ctx_state and is_bpf_ctx_ptr work correctly'
        if is_bpf_ctx_ptr(lhs, info) != rhs_is_ptr:
            error(MODULE_TAG, 'Failed to set the BPF context flag on reference', lhs)

        if backward_jmp_ctx is not None and rhs_is_ptr:
            backward_jmp_ctx.append(lhs)

    # Check if the BPF context is accessed and add bound checking
    blk = cb_ref.get(BODY)
    for x in [lhs, rhs]:
        # TODO: this API is awful
        R = []
        if is_value_from_bpf_ctx(x, info, R):
            ref, index, T = R.pop()
            if ref.change_applied & Instruction.BOUND_CHECK_FLAG != 0:
                continue

            assert isinstance(ref, Instruction)
            assert isinstance(index, Instruction)

            _check_if_variable_index_should_be_masked(ref, index, blk, info)

            ctx_ref = info.prog.get_ctx_ref()
            end_ref = ctx_ref.get_ref_field('data_end', info)
            data_end = Cast.build(end_ref, BASE_TYPES[clang.TypeKind.ULONGLONG])
            __tmp = get_ret_inst(current_function, info)
            if __tmp.body.has_children():
                _ret_inst = get_ret_inst(current_function, info).body.children[0]
            else:
                _ret_inst = None
            check_inst = bpf_ctx_bound_check(ref, index, data_end, _ret_inst)
            blk.append(check_inst)

            ref.change_applied |= Instruction.BOUND_CHECK_FLAG

            # Report for debuging
            tmp,_ = gen_code([inst], info)
            # debug(f'Add a bound check before:\n    {tmp}')
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
        decl = Record.directory.get(name)
        if not decl:
            error(f'Did not found the definition of the Record {T.spelling}')
            return False

        # First check if any of the fields are BPF context
        for field in decl.fields:
            ref_field = Ref.build(field.name, field.type_ref, is_member=True)
            ref_field.owner = [ref,] + ref.owner
            if is_bpf_ctx_ptr(ref_field, info):
                if field_name is not None:
                    field_name.fields.append([ref_field,])
                    found = True
                    field_name.count_bpf_fields += 1
                    # debug(MODULE_TAG, ref.name, field.name, 'is BPF CTX')
        # Check if any of the field has an object which is BPF context
        # for field in decl.fields:
        #     if _has_bpf_ctx_in_field(field, info, field_name):
        #         return True
        # TODO: it might have a field of the type from the parent class. There would be a recursion here which I might not be able to solve.
    return found


def _check_passing_bpf_context(inst, func, info):
    callee_scope = info.sym_tbl.scope_mapping[func.name]
    receives_bpf_ctx = False

    # Find BPF pointers passed to a function
    for pos, a in enumerate(inst.args):
        param = func.args[pos]
        if is_bpf_ctx_ptr(a, info):
            # debug(f'Passing BPF_CTX as argument {param.name} <-- {a.name}')
            sym = callee_scope.lookup(param.name)
            sym.is_bpf_ctx = True
            receives_bpf_ctx = True
        else:
            if not isinstance(a, Ref):
                error('I am not checking whether the argument which are not simple references (e.g, are operations) have BPF context as a field or not')
                continue
            if param.type_ref.spelling != a.type.spelling:
                error('There is a type cast when passing the argument. I lose track of BPF context when there is a type cast! [1]')
                debug(f'param: {param.type_ref.spelling}    argument: {a.type.spelling}')
                continue
            fields = FoundFields()
            # debug(callee_scope.symbols)
            if _has_bpf_ctx_in_field(a, info, fields):
                param_sym = callee_scope.lookup(param.name)
                assert param_sym is not None, 'We should have all the parameters in the scope of functions'
                # debug('fields:', field)
                for field in fields.fields:
                    scope = param_sym.fields
                    for ref in reversed(field):
                        sym = scope.lookup(ref.name)
                        if sym is None:
                                sym = scope.insert_entry(ref.name, ref.type, clang.CursorKind.MEMBER_REF_EXPR, None)
                        scope = sym.fields
                    sym.is_bpf_ctx = True
                    receives_bpf_ctx = True
                    # debug(f'Set the {param.name} .. {sym.name} to BPF_CTX')
            else:
                # debug(f'Does not have BPF CTX in its field {a.name}')
                pass
    return receives_bpf_ctx


def _check_setting_bpf_context_in_callee(inst, func, info):
    callee_scope = info.sym_tbl.scope_mapping[func.name]

    # Check if value of pointers passed to this function was changed to point to BPF context
    # NOTE: it is important that this code be in the context of caller function
    for param, argum in zip(func.get_arguments(), inst.get_arguments()):
        # TODO: do I need to skip typedef to get to the udner type ? get_typedef_under(param.type_ref)
        if not param.type_ref.is_pointer() and not param.type_ref.is_array():
            # Only pointer and arrays can carry the BPF context to this scope
            continue

        if not isinstance(argum, Ref):
            # TODO: I have not implemented the other cases.
            # A question, How complex can it get?
            continue

        # debug(f'Parameter {param.name} ({param.type_ref.kind}) is given argument {argum.owner} {argum.name} ({argum.type})')

        # If the pointer it self is set to be BPF context, then the pointer will be BPF context in this scope too.
        param_sym  = callee_scope.lookup(param.name)
        assert param_sym is not None, f'The function parameters should be found in its symbol table\'s scope ({param.name})'
        argum_sym = get_ref_symbol(argum, info)
        assert argum_sym is not None

        if param_sym.is_bpf_ctx:
            argum_sym.is_bpf_ctx = True
            # report(argum.owner, argum.name, 'is bpf context')

            if backward_jmp_ctx:
                backward_jmp_ctx.append(argum)

        if param.type_ref.spelling != argum.type.spelling:
            error('There is a type cast when passing the argument. I lose track of BPF context when there is a type cast!')
            error('argument type:', argum.type.spelling, 'parameter type:', param.type_ref.spelling)
            continue

        if param.type_ref.is_pointer():
            ptr_type = param.type_ref.get_pointee()
            ptr_type = skip_typedef(ptr_type)
            # NOTE: If the pointer is to a structure, then check if each field of that pointer is set to BPF.
            # Recursion here!
            if ptr_type.is_record():
                for key, entry in param_sym.fields.symbols.items():
                    # propagate the state of being BPF context or not from the callee scope to caller scope
                    e2 = argum_sym.fields.lookup(key)
                    if e2 is None:
                        e2 = argum_sym.fields.insert_entry(entry.name, entry.type, entry.kind, None)
                    e2.is_bpf_ctx = entry.is_bpf_ctx
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
    # caller_scope = info.sym_tbl.current_scope
    # callee_scope = info.sym_tbl.scope_mapping[func.name]

    receives_bpf_ctx = _check_passing_bpf_context(inst, func, info)
    if receives_bpf_ctx:
        _pass_ctx_to_func_if_needed(inst, func, info)

    # Check to not repeat analyzing same function multiple times.
    # if inst.name not in _has_processed_func:
    # _has_processed_func.add(inst.name)
    with new_backward_jump_context(off=True):
        with info.sym_tbl.with_func_scope(inst.name):
            with set_current_func(func):
                func.body = _do_pass(func.body, info, PassObject())

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

        if inst.name in ('memcpy', 'memmove', 'strcpy',):
            # TODO: this is handing memcpy, handle other known fucntions
            ref = inst.args[0]
            size = inst.args[2]

            if ref.change_applied & Instruction.BOUND_CHECK_FLAG != 0:
                return inst

            blk = cb_ref.get(BODY)
            # text, _ = gen_code(blk, info)
            # debug(text)
            # text, _ = gen_code([inst,], info)
            # debug(text)
            _check_if_variable_index_should_be_masked(ref, size, blk, info)
            # Add the check a line before this access
            ctx_ref = info.prog.get_ctx_ref()
            end_ref = ctx_ref.get_ref_field('data_end', info)
            data_end = Cast.build(end_ref, BASE_TYPES[clang.TypeKind.ULONGLONG])
            __tmp = get_ret_inst(current_function, info)
            if __tmp.body.has_children():
                _ret_inst = __tmp.body.children[0]
            else:
                _ret_inst = None
            check_inst = bpf_ctx_bound_check_bytes(ref, size, data_end, _ret_inst)
            blk.append(check_inst)
            ref.change_applied |= Instruction.BOUND_CHECK_FLAG
        elif inst.name in ('__strlen', ):
            ref = inst.args[0]
            if ref.change_applied & Instruction.BOUND_CHECK_FLAG != 0:
                return inst

            blk = cb_ref.get(BODY)
            _check_if_variable_index_should_be_masked(ref, None, blk, info)
            # Add the check a line before this access
            ctx_ref = info.prog.get_ctx_ref()
            end_ref = ctx_ref.get_ref_field('data_end', info)
            data_end = Cast.build(end_ref, BASE_TYPES[clang.TypeKind.ULONGLONG])
            __tmp = get_ret_inst(current_function, info)
            if __tmp.body.has_children():
                _ret_inst = __tmp.body.children[0]
            else:
                _ret_inst = None
            assert 0, 'What range of access should be checked? size is not defined in this scope!'
            check_inst = bpf_ctx_bound_check_bytes(ref, size, data_end, _ret_inst)
            blk.append(check_inst)
            ref.change_applied |= Instruction.BOUND_CHECK_FLAG
        elif inst.name not in itertools.chain(OUR_IMPLEMENTED_FUNC, WRITE_PACKET):
            # We can not modify this function
            error(MODULE_TAG, 'function:', inst.name,
                'receives BPF context but is not accessible for modification')
        else:
            # debug('<><><>', inst.name, 'I only considered some functions, also check for other mem access functions')
            pass
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

        if inst.kind in MAY_HAVE_BACKWARD_JUMP_INSTRUCTIONS:
            # This is a loop (may jump back), go through the loop once,
            # remember which fields my be BPF Context
            with new_backward_jump_context() as marked_refs:
                _do_pass(inst.body, info, PassObject())
                # debug('in a loop these were marked:')
                for ref in marked_refs:
                    # debug(ref)
                    set_ref_bpf_ctx_state(ref, True, info)
                # debug('----------------------------')

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
    with set_current_func(None):
        return _do_pass(inst, info, more)
