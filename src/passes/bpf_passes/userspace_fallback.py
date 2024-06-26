from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
import template
from data_structure import *
from instruction import *
from my_type import MyType
from passes.pass_obj import PassObject
from passes.update_original_ref import set_original_ref
from helpers.instruction_helper import (UINT, ZERO, CHAR, decl_new_var, VOID, VOID_PTR,
        NULL, get_ret_inst, get_or_decl_ref, get_ref_symbol)
from elements.after import After
from var_names import (FAIL_FLAG_NAME, UNIT_MEM_FIELD, UNIT_SIZE,
        CHANNEL_UNITS, CHANNEL_VAR_NAME, UNIT_STRUCT_NMAE, CHANNEL_MAP_NAME,
        ZERO_VAR, DATA_VAR, SEND_FLAG_NAME)
from sym_table import SymbolTableEntry


MODULE_TAG = '[Userspace Fallback]'

current_function = None
cb_ref = CodeBlockRef()
_has_processed = set()
declare_at_top_of_func = []


@contextmanager
def _new_top_func_declare_context():
    global declare_at_top_of_func
    tmp = declare_at_top_of_func
    declare_at_top_of_func = []
    try:
        yield declare_at_top_of_func
    finally:
        declare_at_top_of_func = tmp


@contextmanager
def remember_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield None
    finally:
        current_function = tmp


def _do_move_struct(info, struct_ref, variables, field_names):
    insts = []
    debug(struct_ref, tag=MODULE_TAG)
    for v, fname in zip(variables, field_names):
        field = struct_ref.get_ref_field(fname, info)
        # NOTE: I am assuming that the field and variable are the same type
        # TODO: Check/Assert that field and variable are the same type
        T = v.type
        if T.is_array():
            el_T = T.element_type
            if el_T.is_pointer() or el_T.is_array() or el_T.is_record():
                error(f'How am I going to share an array of elements with non-primitive type? ({v})', tag=MODULE_TAG)
                comment = Literal('/* Copying this array may not be helpful */', CODE_LITERAL)
                insts.append(comment)
            size = Literal(str(T.element_count),
                    clang.CursorKind.INTEGER_LITERAL)
            copy = template.constant_mempcy(field, v, size)
            insts.append(copy)
        elif T.is_pointer():
            sym = get_ref_symbol(v, info)
            assert sym is not None, 'Failed to find the symbol for the variable/field reference'
            if sym.is_bpf_ctx:
                pkt = info.prog.get_pkt_buf()
                data, tmp_decl  = get_or_decl_ref(info, DATA_VAR, VOID_PTR,
                        init=pkt)
                declare_at_top_of_func.extend(tmp_decl)

                # TODO: this code snippet should not exist. But since we are
                # not expecting var_decl + init after simplification, I have to
                # do it manually. Updating the verifier to support init block
                # would solve the issue (or splitting the declaration from
                # initialization for __data)
                sym = info.sym_tbl.lookup(data.name)
                assert sym is not None, 'we have just declared the __data, it should not be None'
                sym.is_bpf_ctx = True

                tmp_v  = Cast.build(v, VOID_PTR)
                off    = BinOp.build(tmp_v, '-', data)
                off    = Cast.build(off, VOID_PTR)
                assign = BinOp.build(field, '=', off)
                insts.append(assign)
            else:
                error('How I am going to share a pointer with userspace?')
                comment = Literal('/* Copying an address to the shared memory is useless! */', CODE_LITERAL)
                insts.append(comment)
                assign = BinOp.build(field, '=', v)
                insts.append(assign)
        elif T.is_record():
            record = T.get_decl()
            if record is None:
                error(f'Failed to find the struct declaration for {T.spelling}', tag=MODULE_TAG)
                comment = Literal(f'/* failed to copy field {v} to {field} */', CODE_LITERAL)
                insts.append(comment)
            else:
                field_refs = [v.get_ref_field(f.name, info) for f in record.fields]
                subfield_names = [f.name for f in field_refs]
                tmp_insts = _do_move_struct(info, field, field_refs, subfield_names)
                insts.extend(tmp_insts)
        else:
            assign = BinOp.build(field, '=', v)
            insts.append(assign)
    return insts


def _move_fallback_vars_to_channel(info, index, failure_number):
    tbl = info.sym_tbl
    to_be_moved = []
    for sym in tbl.current_scope.symbols.values():
        if failure_number not in sym.is_fallback_var:
            continue
        to_be_moved.append(sym)

    if len(to_be_moved) == 0:
        # Nothing to do
        return [], []

    if failure_number not in info.user_prog.declarations:
        error('Did not found the failure meta-data structure defenition', tag=MODULE_TAG)
        return [], []
    meta = info.user_prog.declarations[failure_number]
    decls = []

    tmp_name = f'struct {UNIT_STRUCT_NMAE}'
    T = MyType.make_simple(tmp_name, clang.TypeKind.RECORD)
    T = MyType.make_pointer(T)
    c, tmp = get_or_decl_ref(info, CHANNEL_VAR_NAME, T)
    decls.extend(tmp)

    insts = []
    call = Call(None)
    call.name = 'bpf_map_lookup_elem'
    tmp_map_ref = UnaryOp.build('&', Ref.build(CHANNEL_MAP_NAME, VOID))
    call.args = [tmp_map_ref, index]
    assign = BinOp.build(c, '=', call)

    cond  = BinOp.build(c, '==', NULL)
    check = ControlFlowInst.build_if_inst(cond)
    ret = get_ret_inst(current_function, info)
    check.body.add_inst(ret)
    check.likelihood = Likelihood.Unlikely

    insts.append(assign)
    insts.append(check)

    mem_field = c.get_ref_field(UNIT_MEM_FIELD, info)

    T = MyType.make_pointer(meta.type)
    common_number = meta.name.split('_')[1]
    c_casted, tmp = get_or_decl_ref(info, f'__m{common_number}', T)
    decls.extend(tmp)
    assign = BinOp.build(c_casted, '=', Cast.build(mem_field, T))
    insts.append(assign)

    variables = [Ref.from_sym(sym) for sym in to_be_moved]
    field_names = [r.name for r in variables]
    tmp_insts = _do_move_struct(info, c_casted, variables, field_names)
    insts.extend(tmp_insts)
    return insts, decls


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
    decl_new_var(UINT, info, declare_at_top_of_func, name=FAIL_FLAG_NAME)
    flag_decl = declare_at_top_of_func[-1]
    flag_decl.init.add_inst(ZERO)


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
    # Group failure paths that are similar
    failure_ids = sorted(list(func.path_ids))
    all_symbols = tuple(info.sym_tbl.current_scope.symbols.values())
    get_path_vars = lambda p: tuple(sym
                            for sym in all_symbols
                                if p in sym.is_fallback_var)
    groups = []
    skip = set()
    for i, path_id1 in enumerate(failure_ids):
        if path_id1 in skip:
            continue
        V1 = get_path_vars(path_id1)
        group = [path_id1,]
        for path_id2 in failure_ids[i+1:]:
            V2 = get_path_vars(path_id2)
            if len(V1) != len(V2):
                continue
            same = all(map(lambda x: x[0] == x[1], zip(V1,V2)))
            if not same:
                continue
            group.append(path_id2)
            skip.add(path_id2)
        groups.append(group)

    # Prepare instructions
    decl = []

    switch      = ControlFlowInst()
    switch.kind = clang.CursorKind.SWITCH_STMT
    switch.cond.add_inst(flag_ref)
    switch.set_modified(InstructionColor.CHECK)

    break_inst = Instruction()
    break_inst.kind = clang.CursorKind.BREAK_STMT
    case = CaseSTMT(None)
    case.case.add_inst(ZERO)
    case.body.add_inst(break_inst)
    switch.body.add_inst(case)

    # debug(f'failure numbers for func {func.name}:', failure_ids, tag=MODULE_TAG)
    # for failure_number in failure_ids:
    for group in groups:
        old_case = None
        # Created fall-through cases
        for path_id in group:
            int_literal = Literal(str(path_id),
                                        clang.CursorKind.INTEGER_LITERAL)
            tmp_case = CaseSTMT(None)
            tmp_case.case.add_inst(int_literal)
            # if old_case is not None:
            #     old_case.body.add_inst(tmp_case)
            switch.body.add_inst(tmp_case)
            old_case = tmp_case
        
        # Create instructions moving values
        failure_number = group[0]
        assert failure_number > 0, 'The zero can not be a failure id'

        # TODO: think about the index value
        zero, tmp = get_or_decl_ref(info, ZERO_VAR, UINT, init=ZERO)
        decl.extend(tmp)
        zero_ref = UnaryOp.build('&', zero)

        tmp, tmp_decl = _move_fallback_vars_to_channel(info, zero_ref, failure_number)
        decl.extend(tmp_decl)

        _case = old_case
        _case.body.extend_inst(tmp)

        to_user = ToUserspace.from_func_obj(current_function)
        to_user.set_modified(InstructionColor.TO_USER)
        _case.body.add_inst(to_user)
    return switch, decl


def _process_call_needing_send_flag(inst, info):
    """
    @param inst, a Call object for a Function which needs a send flag
    @return Instruction
    """
    assert isinstance(inst, Call)

    blk = cb_ref.get(BODY)
    sym = info.sym_tbl.lookup(SEND_FLAG_NAME)
    assert sym is not None, 'The function shuold alread received the send flag!'
    flag_ref = Ref.from_sym(sym)
    if flag_ref.type.is_pointer():
        assert current_function is not None, 'We are not at the main function scope, expecting the send flag to be a pointer'
        flag_val = UnaryOp.build('*', flag_ref)
    else:
        assert current_function is None, 'We are not at the main function scope, expecting the send flag to be a scalar'
        flag_val = flag_ref
    cond  = BinOp.build(flag_val, '!=', ZERO)
    cond.set_modified()
    check = ControlFlowInst.build_if_inst(cond)
    check.set_modified(InstructionColor.CHECK)
    if current_function is None:
        # Do we need modify the packet before sending? (e.g., swap IP address)
        before_send_insts = info.prog.before_send()
        check.body.extend_inst(before_send_insts)
        # Return the verdict
        tmp_inst, tmp_decl = info.prog.get_send(info)
        declare_at_top_of_func.extend(tmp_decl)
        check.body.extend_inst(tmp_inst[:-1])
        ret_val  = tmp_inst[-1]
        ret_inst = Return.build([ret_val,])
        # It is not marked as 'InstructionColor.REMOVE_WRITE'
        # because the instruction was removed inside the
        # called funcation and we count it there.
        ret_inst.set_modified()
        check.body.add_inst(ret_inst)
    else:
        # Return to the caller func
        ret_inst = get_ret_inst(current_function, info)
        check.body.add_inst(ret_inst)
    set_original_ref(check, info, inst.original)
    after = After([check,])
    blk.append(after)
    return inst


def _handle_call_may_fail_or_succeed(inst, func, info, more):
    ctx = more.ctx
    blk = cb_ref.get(BODY)
    after_func_call = []
    assert (func.change_applied & Function.FAIL_FLAG) != 0, f'The fail flag should alread be added to the function definition (func:{func.name})'
    assert len(func.path_ids) > 0, f'why there is no associated failure path? {func.name}'

    sym = info.sym_tbl.lookup(FAIL_FLAG_NAME)
    assert sym is not None, 'By now the flag should be defined'
    flag_ref = Ref.from_sym(sym)

    tmp = Literal('/* check if function fail */\n', CODE_LITERAL)
    after_func_call.append(tmp)

    if current_function == None:
        tmp_inst, tmp_decl = \
            _generate_failure_flag_check_in_main_func_switch_case(flag_ref,
                    func, info)
        declare_at_top_of_func.extend(tmp_decl)
        set_original_ref(tmp_inst, info, inst.original)
    else:
        flag_val = UnaryOp.build('*', flag_ref)
        cond = BinOp.build(flag_val , '!=', ZERO)
        check_failed = ControlFlowInst.build_if_inst(cond)
        switch, tmp_decl = \
            _generate_failure_flag_check_in_main_func_switch_case(flag_val,
                    func, info)
        declare_at_top_of_func.extend(tmp_decl)
        check_failed.body.add_inst(switch)
        check_failed.set_modified(InstructionColor.CHECK)
        tmp_inst = check_failed
        set_original_ref(tmp_inst, info, inst.original)
    after_func_call.append(tmp_inst)

    # Analyse the called function
    if func.name not in _has_processed:
        _has_processed.add(func.name)
        with remember_func(func):
            with info.sym_tbl.with_func_scope(func.name):
                with _new_top_func_declare_context():
                    body = _do_pass(func.body, info, PassObject())
                    body.children = declare_at_top_of_func + body.children
                    func.body = body
    blk.append(After(after_func_call))
    return inst


def _handle_call_may_fail(inst, func, info, more):
    assert not func.may_succeed, 'handling calls that may fail or succeed are moved to another function'
    assert 0, 'is this code path used at all?'
    ctx = more.ctx
    blk = cb_ref.get(BODY)
    before_func_call = []
    after_func_call = []
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
        if not func or func.is_empty():
            return inst

        orig_inst = inst
        if func.calls_send:
            inst = _process_call_needing_send_flag(inst, info)

        # Check for function failures
        if not func.may_fail:
            return inst
        if func.may_succeed:
            return _handle_call_may_fail_or_succeed(inst, func, info, more)
        return _handle_call_may_fail(inst, func, info, more)
    elif inst.kind == TO_USERSPACE_INST:
        blk = cb_ref.get(BODY)
        failure_num = inst.path_id
        if current_function is None:
            # Found a fallback point on the BPF entry function
            # meta = info.user_prog.declarations.get(failure_num)
            # assert meta is not None, f'did not found the metadata structure declaration for failure: {failure_num}'

            # TODO: think about the index value
            zero, tmp = get_or_decl_ref(info, ZERO_VAR, UINT, init=ZERO)
            declare_at_top_of_func.extend(tmp)
            zero_ref = UnaryOp.build('&', zero)
            prepare_pkt, tmp_decl = _move_fallback_vars_to_channel(info, zero_ref, failure_num)
            declare_at_top_of_func.extend(tmp_decl)
            blk.extend(prepare_pkt)

            # Add instructions needed before passing the packet to the kernel
            before_pass = info.prog.before_pass()
            blk.extend(before_pass)
        else:
            sym = info.sym_tbl.lookup(FAIL_FLAG_NAME)
            if sym is None:
                _decl_failure_flag_on_stack(info)
                sym = info.sym_tbl.lookup(FAIL_FLAG_NAME)
            assert sym is not None, 'We want to set the failure flag, it should be already defined!'
            set_failuer = _set_failure_flag(failure_num, sym.type.is_pointer())
            set_failuer.set_modified(InstructionColor.EXTRA_MEM_ACCESS)
            blk.append(set_failuer)

            # TODO: think about the index value
            zero, tmp = get_or_decl_ref(info, ZERO_VAR, UINT, init=ZERO)
            declare_at_top_of_func.extend(tmp)
            zero_ref = UnaryOp.build('&', zero)
            prepare_pkt, tmp_decl = _move_fallback_vars_to_channel(info, zero_ref, failure_num)
            declare_at_top_of_func.extend(tmp_decl)
            blk.extend(prepare_pkt)
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


def _declare_shared_channel(info):
    sym_tbl = info.sym_tbl
    struct_name = UNIT_STRUCT_NMAE
    T = MyType.make_array('__unset_type_name__', CHAR, UNIT_SIZE)
    fields = [StateObject.build(UNIT_MEM_FIELD, T),]
    unit_decl = Record(struct_name, fields)
    unit_decl.is_used_in_bpf_code = True
    info.prog.add_declaration(unit_decl)
    # Update symbol table
    ss = sym_tbl.sk_state_scope
    with sym_tbl.with_scope(ss):
        unit_decl.update_symbol_table(sym_tbl)
    # Create a BPF ARRAY MAP using this new structure
    m = BPFMap.build_arr_map(CHANNEL_MAP_NAME, unit_decl.type, CHANNEL_UNITS)
    m.is_used_in_bpf_code = True
    info.prog.add_declaration(m)


def userspace_fallback_pass(inst, info, more):
    """
    This pass implements the communication protocol between BPF and user
    program inside the generated BPF program.
    """
    _declare_shared_channel(info)
    with remember_func(None):
        with _new_top_func_declare_context():
            body = _do_pass(inst, info, more)
            body.children = declare_at_top_of_func + body.children
    return body
