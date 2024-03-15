from instruction import *
from data_structure import *
from my_type import MyType
from utility import get_tmp_var_name
from helpers.bpf_ctx_helper import is_bpf_ctx_ptr
from helpers.instruction_helper import (get_ret_inst, decl_new_var, ZERO, NULL,
        CHAR_PTR, INT, NULL_CHAR, UINT, ONE, VOID_PTR)
from elements.likelihood import Likelihood
from var_names import DATA_VAR, ITERATOR_VAR


def bpf_ctx_bound_check(ref, index, data_end, func, abort=False):
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

    _if.cond.add_inst(cond)
    _if.likelihood = Likelihood.Unlikely
    if abort:
        tmp_ret = get_ret_inst(func)
        _if.body.add_inst(tmp_ret)
    else:
        _if.body.add_inst(ToUserspace.from_func_obj(func))
    return _if


def bpf_ctx_bound_check_bytes(ref, size, data_end, func, abort=False):
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

    _if.cond.add_inst(cond)
    _if.body.add_inst(ToUserspace.from_func_obj(func))
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
def prepare_shared_state_var(func):
    var_decl = VarDecl.build('shared', SHARED_OBJ_PTR, red=True)
    var_decl.init.add_inst(NULL)
    var_ref = var_decl.get_ref()
    var_ref.set_modified()

    zero_decl = VarDecl.build(get_tmp_var_name(), UINT, red=True)
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
    check.body.add_inst(ToUserspace.from_func_obj(func))
    check.likelihood = Likelihood.Unlikely
    check.set_modified(InstructionColor.CHECK)
    insts = [var_decl, zero_decl, lookup_assign,  check]
    return insts


def prepare_meta_data(failure_number, meta_declaration, info, func):
    decl = []
    type_name = f'struct {meta_declaration.name}'
    req_type = MyType.make_simple(type_name, clang.TypeKind.RECORD)
    T = MyType.make_pointer(req_type)

    target_size_inst = Literal(f'sizeof({req_type.spelling})', CODE_LITERAL)
    adjust_inst, tmp_decl = info.prog.adjust_pkt(target_size_inst, info)
    decl.extend(tmp_decl)

    # tmp_name = DATA_VAR
    # sym = info.sym_tbl.lookup(tmp_name)
    # if not sym:
    #     ref = decl_new_var(T, info, decl, name=DATA_VAR)
    # else:
    #     ref = Ref.from_sym(sym)
    ref = decl_new_var(T, info, decl)
    assign = BinOp.build(ref, '=', info.prog.get_pkt_buf())
    assign.set_modified()

    # DROP = Literal(info.prog.get_drop(), clang.CursorKind.INTEGER_LITERAL)
    # DROP.set_modified()
    bound_check = bpf_ctx_bound_check(ref, ZERO, info.prog.get_pkt_end(), func,
            abort=True)

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
    return define_bpf_map(map_name, 'BPF_MAP_TYPE_ARRAY',
            'unsigned int', val_type, entries)


def define_bpf_hash_map(map_name, key_type, val_type, entries):
    return define_bpf_map(map_name, 'BPF_MAP_TYPE_HASH', key_type,
            val_type, entries)


def malloc_lookup(name, info, func):
    """
    """
    decls = []
    insts = []
    type_name = f'struct {name}'
    struct_T = MyType.make_simple(type_name, clang.TypeKind.RECORD)
    T = MyType.make_pointer(struct_T)

    # Add var decl to symbol table
    ref = decl_new_var(T, info, decls)
    zero = decl_new_var(T, info, decls)

    # zero = 0
    tmp_assign = BinOp.build(zero, '=', ZERO, red=True)
    insts.append(tmp_assign)

    # ref = bpf_map_lookup_elem(&map, &zero)
    lookup = Call(None)
    lookup.name = 'bpf_map_lookup_elem'
    map_ref = UnaryOp.build('&', Ref.build(f'{name}_map', struct_T))
    lookup.args = [map_ref, UnaryOp.build('&', zero)]
    lookup.set_modified(InstructionColor.MAP_LOOKUP)
    tmp_assign = BinOp.build(ref, '=', lookup, red=True)
    insts.append(tmp_assign)

    # if (ref == NULL) {}
    cond = BinOp.build(ref, '==', NULL)
    check = ControlFlowInst.build_if_inst(cond, red=True)
    check.body.add_inst(ToUserspace.from_func_obj(func))
    insts.append(check)

    #Inst: tmp->data
    owner = Ref(None)
    owner.name = ref.name
    owner.type = T
    owner.kind = clang.CursorKind.DECL_REF_EXPR
    ref = Ref(None)
    ref.name = 'data'
    ref.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
    ref.kind = clang.CursorKind.MEMBER_REF_EXPR
    ref.owner.append(owner)
    ref.set_modified()

    return insts, decls, ref


_loop_var_name_counter = 0
def _get_temp_loop_var_name():
    global _loop_var_name_counter
    _loop_var_name_counter += 1
    name = f'_i{_loop_var_name_counter}'
    return name


def new_bounded_loop(var_bound, max_bound, info, func, loop_var_type=INT):
    decl = []

    _tmp_name = _get_temp_loop_var_name()
    loop_var = decl_new_var(loop_var_type, info, decl, name=_tmp_name)

    # _tmp_name = ITERATOR_VAR
    # sym = info.sym_tbl.lookup(_tmp_name)
    # if sym is None:
    #     loop_var = decl_new_var(loop_var_type, info, decl, name=_tmp_name)
    # else:
    #     loop_var = Ref.from_sym(sym)

    initialize = BinOp.build(loop_var, '=', ZERO)

    if var_bound == max_bound:
        condition = BinOp.build(loop_var, '<', max_bound)
    else:
        max_bound_check = BinOp.build(loop_var, '<', max_bound)
        var_bound_check = BinOp.build(loop_var, '<', var_bound)
        condition = BinOp.build(max_bound_check, '&&', var_bound_check)

    post = UnaryOp.build('++', loop_var)
    loop = ForLoop.build(initialize, condition, post)
    # loop.repeat = max_bound.text # does this work?
    loop.set_modified()

    insts = [loop,]
    if var_bound != max_bound:
        failure_cond = BinOp.build(loop_var, '>=', max_bound)
        check_bound_failure = ControlFlowInst.build_if_inst(failure_cond)
        check_bound_failure.body.add_inst(ToUserspace.from_func_obj(func))
        insts.append(check_bound_failure)
    return insts, decl, loop_var


def _add_paranthesis_if_needed(inst):
    if isinstance(inst, (UnaryOp, BinOp, Cast)):
        new = Parenthesis.build(inst)
        return new
    return inst


def constant_mempcy(dst, src, size):
    copy         = Call(None)
    copy.name    = 'memcpy'
    args         = [dst, src, size]
    copy.args = args
    return copy


def variable_memcpy(dst, src, size, up_bound, info, func):
    declare_at_top_of_func = []
    max_bound = Literal(str(up_bound), clang.CursorKind.INTEGER_LITERAL)

    src = _add_paranthesis_if_needed(src)
    dst = _add_paranthesis_if_needed(dst)

    if not hasattr(src, 'type'):
        src = Cast.build(src, CHAR_PTR)
    if not hasattr(dst, 'type'):
        dst = Cast.build(dst, CHAR_PTR)

    tmp_insts, tmp_decl, loop_var = new_bounded_loop(size, max_bound, info,
            func, UINT)
    loop = tmp_insts[0]
    declare_at_top_of_func.extend(tmp_decl)

    at_src = ArrayAccess.build(src, loop_var)
    at_dst = ArrayAccess.build(dst, loop_var)
    copy = BinOp.build(at_dst, '=', at_src)
    copy.set_modified()
    loop.body.add_inst(copy)
    return tmp_insts, declare_at_top_of_func, dst


def strncmp(s1, s2, size, upper_bound, info, func):
    assert hasattr(s1, 'type')
    assert hasattr(s2, 'type')
    assert s1.type.is_pointer() or s1.type.is_array()
    assert s1.type.under_type.spelling in ('char', 'unsigned char')
    assert s2.type.is_pointer() or s2.type.is_array()
    assert s2.type.under_type.spelling in ('char', 'unsigned char'), f'{s2.type.under_type.spelling} is not char!'

    s1 = _add_paranthesis_if_needed(s1)
    s2 = _add_paranthesis_if_needed(s2)

    decl = []
    if size != upper_bound:
        max_bound = Literal(str(upper_bound), clang.CursorKind.INTEGER_LITERAL)
    else:
        max_bound = size

    res_var = decl_new_var(INT, info, decl)
    init_res = BinOp.build(res_var, '=', ZERO)

    tmp_insts, tmp_decl, loop_var = new_bounded_loop(size, max_bound, info,
            func, UINT)
    loop = tmp_insts[0]
    decl.extend(tmp_decl)

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

    tmp_insts.insert(0, init_res)
    return tmp_insts, decl, res_var


def strlen(s, max_bound, info, func):
    assert hasattr(s, 'type')
    assert s.type.is_pointer() or s.type.is_array()
    assert s.type.under_type.spelling in ('char', 'unsigned char'), f'unexpected type {s.type.under_type.spelling}'
    s = _add_paranthesis_if_needed(s)
    decl = []
    max_bound = Literal(str(max_bound), clang.CursorKind.INTEGER_LITERAL)
    res_var = decl_new_var(UINT, info, decl)
    init_res = BinOp.build(res_var, '=', ZERO)

    tmp_insts, tmp_decl, loop_var = new_bounded_loop(max_bound, max_bound,
            info, func, UINT)
    loop = tmp_insts[0]
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

    tmp_insts.insert(0, init_res)
    return tmp_insts, decl, res_var

def strncpy(s1, s2, size, max_bound, info, func):
    assert hasattr(s1, 'type')
    assert hasattr(s2, 'type')
    assert s1.type.is_pointer() or s1.type.is_array()
    assert s1.type.under_type.spelling in ('char', 'unsigned char'), f'{s2.type.under_type.spelling} is not char!'
    assert s2.type.is_pointer() or s2.type.is_array()
    assert s2.type.under_type.spelling in ('char', 'unsigned char'), f'{s2.type.under_type.spelling} is not char!'
    s1 = _add_paranthesis_if_needed(s1)
    s2 = _add_paranthesis_if_needed(s2)
    decl = []
    if size != max_bound:
        max_bound = Literal(str(max_bound), clang.CursorKind.INTEGER_LITERAL)
    # strncpy returns a pointer to the destination string
    res_var = s1
    # Creat the loop
    tmp_insts, tmp_decl, loop_var = new_bounded_loop(size, max_bound, info,
            func, UINT)
    loop = tmp_insts[0]
    decl.extend(tmp_decl)

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
