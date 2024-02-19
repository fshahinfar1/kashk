from instruction import *
from data_structure import *
from utility import get_tmp_var_name
from helpers.bpf_ctx_helper import is_bpf_ctx_ptr
from helpers.instruction_helper import decl_new_var, ZERO, NULL, CHAR_PTR, INT, NULL_CHAR, UINT, ONE
from elements.likelihood import Likelihood

VOID_PTR = 'void *'


def bpf_ctx_bound_check(ref, index, data_end, return_value=None):
    _if = ControlFlowInst()
    _if.kind = clang.CursorKind.IF_STMT
    _if.set_modified(InstructionColor.CHECK)

    # index + 1
    size_plus_one = BinOp(None)
    size_plus_one.op = '+'
    size_plus_one.lhs.add_inst(index)
    size_plus_one.rhs.add_inst(Literal('1', clang.CursorKind.INTEGER_LITERAL))
    size_plus_one.set_modified(InstructionColor.EXTRA_ALU_OP)

    # (ref + index + 1)
    pkt_off = BinOp(None)
    pkt_off.op = '+'
    pkt_off.lhs.add_inst(ref)
    pkt_off.rhs.add_inst(size_plus_one)
    pkt_off.set_modified(InstructionColor.EXTRA_ALU_OP)

    # (void *)(ref + size + 1)
    lhs_cast = Cast()
    lhs_cast.castee.add_inst(pkt_off)
    lhs_cast.type = VOID_PTR

    # (void *)(ref + size + 1) > (void *)(data_end)
    cond = BinOp(None)
    cond.op = '>'
    cond.lhs.add_inst(lhs_cast)
    cond.rhs.add_inst(data_end)
    cond.set_modified(InstructionColor.EXTRA_ALU_OP)

    # return 0
    ret = Return()
    if return_value is None:
        # ret.body.add_inst(Literal('0', kind=clang.CursorKind.INTEGER_LITERAL))
        pass
    else:
        ret.body.add_inst(return_value)
    ret.set_modified()

    _if.cond.add_inst(cond)
    _if.body.add_inst(ret)
    _if.likelihood = Likelihood.Unlikely
    return _if


def bpf_ctx_bound_check_bytes(ref, size, data_end, return_value=None):
    _if = ControlFlowInst()
    _if.kind = clang.CursorKind.IF_STMT
    _if.set_modified(InstructionColor.CHECK)

    # size + 1
    size_plus_one = BinOp(None)
    size_plus_one.op = '+'
    size_plus_one.lhs.add_inst(size)
    size_plus_one.rhs.add_inst(Literal('1', clang.CursorKind.INTEGER_LITERAL))
    size_plus_one.set_modified(InstructionColor.EXTRA_ALU_OP)

    # (void *)(ref)
    lhs_cast = Cast()
    lhs_cast.castee.add_inst(ref)
    lhs_cast.type = VOID_PTR

    # (void *)(ref) + size + 1
    pkt_off = BinOp(None)
    pkt_off.op = '+'
    pkt_off.lhs.add_inst(lhs_cast)
    pkt_off.rhs.add_inst(size_plus_one)
    pkt_off.set_modified(InstructionColor.EXTRA_ALU_OP)

    # (void *)(ref + size + 1) > (void *)(data_end)
    cond = BinOp(None)
    cond.op = '>'
    cond.lhs.add_inst(pkt_off)
    cond.rhs.add_inst(data_end)
    cond.set_modified(InstructionColor.EXTRA_ALU_OP)

    # return 0
    ret = Return()
    if return_value is None:
        ret.body.add_inst(Literal('0', kind=clang.CursorKind.INTEGER_LITERAL))
    else:
        ret.body.add_inst(return_value)
    ret.set_modified()

    _if.cond.add_inst(cond)
    _if.body.add_inst(ret)
    _if.likelihood = Likelihood.Unlikely
    return _if


def license_text(license):
    return f'char _license[] SEC("license") = "{license}";'


def shared_map_decl():
    return '''struct {
  __uint(type,  BPF_MAP_TYPE_ARRAY);
  __type(key,   __u32);
  __type(value, struct shared_state);
  __uint(max_entries, 1);
} shared_map SEC(".maps");
'''


shared_struct = MyType.make_simple('struct shared_state',
        clang.TypeKind.RECORD)
SHARED_OBJ_PTR = MyType.make_pointer(shared_struct)
SHARED_MAP_PTR = Literal('&shared_map', CODE_LITERAL)
def prepare_shared_state_var(ret_val=None):
    var_decl = VarDecl.build('shared', SHARED_OBJ_PTR, red=True)
    var_decl.init.add_inst(NULL)
    var_ref = var_decl.get_ref()
    var_ref.set_modified()

    zero_decl = VarDecl.build(get_tmp_var_name(), INT, red=True)
    zero_decl.init.add_inst(ZERO)
    zero_ref = zero_decl.get_ref()
    zero_ref.set_modified()
    zero_ptr = UnaryOp.build('&', zero_ref)
    zero_ptr.set_modified()

    call_lookup = Call(None)
    call_lookup.name = 'bpf_map_lookup_elem'
    call_lookup.args = [SHARED_MAP_PTR, zero_ptr]
    call_lookup.set_modified(InstructionColor.KNOWN_FUNC_IMPL)

    lookup_assign = BinOp.build(var_ref, '=', call_lookup)
    lookup_assign.set_modified()

    cond  = BinOp.build(var_ref, '==', NULL, red=True)
    check = ControlFlowInst.build_if_inst(cond)
    if ret_val is None:
        ret_val = Return.build([], red=True)
    check.body.add_inst(ret_val)
    check.likelihood = Likelihood.Unlikely
    check.set_modified(InstructionColor.CHECK)
    insts = [var_decl, zero_decl, lookup_assign,  check]
    return insts


def prepare_meta_data(failure_number, meta_declaration, info):
    decl = []
    type_name = f'struct {meta_declaration.name}'
    req_type = MyType.make_simple(type_name, clang.TypeKind.RECORD)
    T = MyType.make_pointer(req_type)

    target_size_inst = Literal(f'sizeof({req_type.spelling})', CODE_LITERAL)
    adjust_inst, tmp_decl = info.prog.adjust_pkt(target_size_inst, info)
    decl.extend(tmp_decl)

    ref = decl_new_var(T, info, decl)
    assign = BinOp.build(ref, '=', info.prog.get_pkt_buf())
    assign.set_modified()

    DROP = Literal(info.prog.get_drop(), clang.CursorKind.INTEGER_LITERAL)
    DROP.set_modified()
    bound_check = bpf_ctx_bound_check(ref, ZERO, info.prog.get_pkt_end(), DROP)

    store = [f'{ref.name}->failure_number = {failure_number};', ]
    for f in meta_declaration.fields[1:]:
        store.append(f'{ref.name}->{f.name} = {f.name};')
    code = '\n'.join(store) + '\n'
    populate = Literal(code, CODE_LITERAL)
    populate.set_modified(InstructionColor.MEM_COPY)

    insts = adjust_inst + [assign, bound_check, populate]
    return insts, decl


def define_bpf_map(map_name, map_type, key_type, val_type, entries):
    return Literal(f'''struct {{
  __uint(type,  {map_type});
  __type(key,   {key_type});
  __type(value, {val_type});
  __uint(max_entries, {entries});
}} {map_name} SEC(".maps");''', CODE_LITERAL)


def define_bpf_arr_map(map_name, val_type, entries):
    return define_bpf_map(map_name, 'BPF_MAP_TYPE_ARRAY', 'unsigned int', val_type, entries)


def define_bpf_hash_map(map_name, key_type, val_type, entries):
    return define_bpf_map(map_name, 'BPF_MAP_TYPE_HASH', key_type, val_type, entries)



def malloc_lookup(name, info, return_val):
    """
    """
    tmp_name = get_tmp_var_name()
    type_name = f'struct {name}'
    T = MyType.make_pointer(MyType.make_simple(type_name, clang.TypeKind.RECORD))

    # Add var decl to symbol table
    info.sym_tbl.insert_entry(tmp_name, T, clang.CursorKind.VAR_DECL, None)

    var_decl = VarDecl(None)
    var_decl.name = tmp_name
    var_decl.type = T
    var_decl.init.add_inst(Literal('NULL', clang.CursorKind.INTEGER_LITERAL))
    var_decl.update_symbol_table(info.sym_tbl)

    text = f'''
{{
  const int zero = 0;
  {tmp_name} = bpf_map_lookup_elem(&{name}_map, &zero);
  if ({tmp_name} == NULL) {{
    return {return_val};
  }}
}}
'''
    lookup_inst = Literal(text, CODE_LITERAL)
    lookup_inst.set_modified(InstructionColor.MAP_LOOKUP)

    #Inst: tmp->data
    owner = Ref(None)
    owner.name = tmp_name
    owner.type = T
    owner.kind = clang.CursorKind.DECL_REF_EXPR
    ref = Ref(None)
    ref.name = 'data'
    ref.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
    ref.kind = clang.CursorKind.MEMBER_REF_EXPR
    ref.owner.append(owner)
    ref.set_modified()

    return [var_decl, lookup_inst], ref


def new_bounded_loop(var_bound, max_bound, info, loop_var_type=INT):
    decl = []
    loop_var = decl_new_var(loop_var_type, info, decl)
    initialize = BinOp.build(loop_var, '=', ZERO)

    max_bound_check = BinOp.build(loop_var, '<', max_bound)
    var_bound_check = BinOp.build(loop_var, '<', var_bound)
    condition = BinOp.build(max_bound_check, '&&', var_bound_check)

    post = UnaryOp.build('++', loop_var)
    loop = ForLoop.build(initialize, condition, post)
    loop.repeat = max_bound
    loop.set_modified()
    return loop, decl, loop_var


def _add_paranthesis_if_needed(inst):
    if isinstance(inst, (UnaryOp, BinOp, Cast)):
        new = Parenthesis.build(inst)
        return new
    return inst


def variable_memcpy(dst, src, size, up_bound, info, fail_return_inst=None):
    declare_at_top_of_func = []
    max_bound = Literal(str(up_bound), clang.CursorKind.INTEGER_LITERAL)
    bound_check_src = is_bpf_ctx_ptr(src, info)
    bound_check_dst = is_bpf_ctx_ptr(dst, info)

    src = _add_paranthesis_if_needed(src)
    dst = _add_paranthesis_if_needed(dst)

    if not hasattr(src, 'type'):
        src = Cast.build(src, CHAR_PTR)
    if not hasattr(dst, 'type'):
        dst = Cast.build(dst, CHAR_PTR)

    T = BASE_TYPES[clang.TypeKind.USHORT]
    loop, tmp_decl, loop_var = new_bounded_loop(size, max_bound, info, T)
    declare_at_top_of_func.extend(tmp_decl)

    if bound_check_src:
        data_end = info.prog.get_pkt_end()
        ret = fail_return_inst
        tmp_check = bpf_ctx_bound_check(src, loop_var, data_end, ret)
        loop.body.add_inst(tmp_check)

    if bound_check_dst:
        data_end = info.prog.get_pkt_end()
        ret = fail_return_inst
        tmp_check = bpf_ctx_bound_check(dst, loop_var, data_end, ret)
        loop.body.add_inst(tmp_check)

    at_src = ArrayAccess.build(src, loop_var)
    at_dst = ArrayAccess.build(dst, loop_var)
    copy = BinOp.build(at_dst, '=', at_src)
    copy.set_modified()
    loop.body.add_inst(copy)
    return loop, declare_at_top_of_func, dst


def strncmp(s1, s2, size, upper_bound, info, fail_return_inst=None):
    assert hasattr(s1, 'type')
    assert hasattr(s2, 'type')
    assert s1.type.is_pointer() or s1.type.is_array()
    assert s1.type.under_type.spelling in ('char', 'unsigned char')
    assert s2.type.is_pointer() or s2.type.is_array()
    assert s2.type.under_type.spelling in ('char', 'unsigned char'), f'{s2.type.under_type.spelling} is not char!'

    s1 = _add_paranthesis_if_needed(s1)
    s2 = _add_paranthesis_if_needed(s2)

    decl = []
    max_bound = Literal(str(upper_bound), clang.CursorKind.INTEGER_LITERAL)
    bound_check_s1 = is_bpf_ctx_ptr(s1, info)
    bound_check_s2 = is_bpf_ctx_ptr(s2, info)


    # debug('strncmp, inputs:')
    # debug('s1:', s1, s1.owner)
    # debug('s2:', s2, s2.owner)
    # debug('bound check needed:', bound_check_s1, bound_check_s2)
    # debug('++++++++++++++++++++++++++++')

    res_var = decl_new_var(INT, info, decl)
    init_res = BinOp.build(res_var, '=', ZERO)

    loop, tmp_decl, loop_var = new_bounded_loop(size, max_bound, info, INT)
    decl.extend(tmp_decl)

    if bound_check_s1:
        data_end = info.prog.get_pkt_end()
        ret = fail_return_inst
        tmp_check = bpf_ctx_bound_check(s1, loop_var, data_end, ret)
        loop.body.add_inst(tmp_check)

    if bound_check_s2:
        data_end = info.prog.get_pkt_end()
        ret = fail_return_inst
        tmp_check = bpf_ctx_bound_check(s2, loop_var, data_end, ret)
        loop.body.add_inst(tmp_check)

    at_s1 = ArrayAccess.build(s1, loop_var)
    at_s2 = ArrayAccess.build(s2, loop_var)
    cmp = BinOp.build(at_s1, '-', at_s2)
    assign = BinOp.build(res_var, '=', cmp)

    tmp_cond = BinOp.build(res_var, '!=', ZERO)
    check = ControlFlowInst.build_if_inst(tmp_cond)
    tmp_brk = Instruction()
    tmp_brk.kind = clang.CursorKind.BREAK_STMT
    check.body.add_inst(tmp_brk)
    loop.body.extend_inst([assign, check])

    insts = [init_res, loop]
    return insts, decl, res_var


def strlen(s, max_bound, info):
    assert hasattr(s, 'type')
    assert s.type.is_pointer() or s.type.is_array()
    assert s.type.under_type.spelling in ('char', 'unsigned char'), f'unexpected type {s.type.under_type.spelling}'
    s = _add_paranthesis_if_needed(s)
    decl = []
    max_bound = Literal(str(max_bound), clang.CursorKind.INTEGER_LITERAL)
    bound_check_s = is_bpf_ctx_ptr(s, info)
    res_var = decl_new_var(INT, info, decl)
    init_res = BinOp.build(res_var, '=', ZERO)

    loop, tmp_decl, loop_var = new_bounded_loop(max_bound, max_bound, info, INT)
    decl.extend(tmp_decl)

    at_s = ArrayAccess.build(s, loop_var)
    tmp_cond = BinOp.build(at_s, '==', NULL_CHAR)
    check = ControlFlowInst.build_if_inst(tmp_cond)
    update_res = BinOp.build(res_var, '=', loop_var)
    tmp_brk = Instruction()
    tmp_brk.kind = clang.CursorKind.BREAK_STMT
    check.body.add_inst(update_res)
    check.body.add_inst(tmp_brk)
    loop.body.add_inst(check)

    insts = [init_res, loop]
    return insts, decl, res_var

def strncpy(s1, s2, size, max_bound, info, fail_return_inst=None):
    assert hasattr(s1, 'type')
    assert hasattr(s2, 'type')
    assert s1.type.is_pointer() or s1.type.is_array()
    assert s1.type.under_type.spelling in ('char', 'unsigned char'), f'{s2.type.under_type.spelling} is not char!'
    assert s2.type.is_pointer() or s2.type.is_array()
    assert s2.type.under_type.spelling in ('char', 'unsigned char'), f'{s2.type.under_type.spelling} is not char!'
    s1 = _add_paranthesis_if_needed(s1)
    s2 = _add_paranthesis_if_needed(s2)
    decl = []
    max_bound = Literal(str(max_bound), clang.CursorKind.INTEGER_LITERAL)
    bound_check_s1 = is_bpf_ctx_ptr(s1, info)
    bound_check_s2 = is_bpf_ctx_ptr(s2, info)

    # strncpy returns a pointer to the destination string
    res_var = s1
    # Creat the loop
    loop, tmp_decl, loop_var = new_bounded_loop(size, max_bound, info, UINT)
    decl.extend(tmp_decl)
    # Performe bound check on the src/dest if needed
    if bound_check_s1:
        data_end = info.prog.get_pkt_end()
        ret = fail_return_inst
        tmp_check = bpf_ctx_bound_check(s1, loop_var, data_end, ret)
        loop.body.add_inst(tmp_check)
    if bound_check_s2:
        data_end = info.prog.get_pkt_end()
        ret = fail_return_inst
        tmp_check = bpf_ctx_bound_check(s2, loop_var, data_end, ret)
        loop.body.add_inst(tmp_check)
    #
    at_s1 = ArrayAccess.build(s1, loop_var)
    at_s2 = ArrayAccess.build(s2, loop_var)
    assign = BinOp.build(at_s1, '=', at_s2)

    null_term_cond = BinOp.build(at_s2, '==', NULL_CHAR)
    size_minus_one = BinOp.build(size, '-', ONE)
    len_cond = BinOp.build(loop_var, '>=', size_minus_one)
    tmp_cond = BinOp.build(null_term_cond, '||', len_cond)
    check = ControlFlowInst.build_if_inst(tmp_cond)
    tmp_brk = Instruction()
    tmp_brk.kind = clang.CursorKind.BREAK_STMT
    check.body.add_inst(tmp_brk)
    loop.body.extend_inst([assign, check])

    insts = [loop]
    return insts, decl, res_var
