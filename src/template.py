from instruction import *
from data_structure import *
from my_type import MyType
from utility import get_tmp_var_name
from helpers.bpf_ctx_helper import is_bpf_ctx_ptr
from helpers.instruction_helper import (get_ret_inst, decl_new_var, ZERO, NULL,
        CHAR_PTR, INT, NULL_CHAR, UINT, ONE, VOID_PTR, VOID)
from elements.likelihood import Likelihood
from var_names import *
from internal_types import *

# Some things defined in global scope
SHARED_MAP_PTR = Literal(f'&{SHARED_MAP_NAME}', CODE_LITERAL)


def bpf_map_lookup_elem(map_name: str, index: Instruction, out: Ref, current_func):
    insts = []
    decl = []
    lookup = Call(None)
    lookup.name = 'bpf_map_lookup_elem'
    map_obj_name = Ref.build(map_name, VOID)
    map_ref = UnaryOp.build('&', map_obj_name)
    lookup.args = [map_ref, index]
    lookup.set_modified(InstructionColor.MAP_LOOKUP)
    assign = BinOp.build(out, '=', lookup, red=True)
    insts.append(assign)
    # check if return value is null
    null_cond = BinOp.build(out, '==', NULL)
    null_check = ControlFlowInst.build_if_inst(null_cond)
    fail = ToUserspace.from_func_obj(current_func)
    null_check.body.add_inst(fail)
    null_check.set_modified(InstructionColor.CHECK)
    insts.append(null_check)
    return insts, decl


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
    return BPFMap.build_arr_map(SHARED_MAP_NAME, SHARED_STRUCT_TYPE, 1)


def skskb_get_flow_id(cur_func, info):
    """
    @returns a tuple of size 3
     0. New instruction to add
     1. New variable declarations
     2. reference to the flow-id object
    """
    from bpf_hook.skskb import SK_SKB_PROG
    assert isinstance(info.prog, SK_SKB_PROG), 'This function is only relevant to SK_SKB hook'
    insts = []
    decl = []

    skb = info.prog.get_ctx_ref()
    sk = skb.get_ref_field('sk', info)
    # sk = Literal(f'{info.prog.ctx}->sk', CODE_LITERAL)
    cond = BinOp.build(sk, '==', NULL)
    check_null = ControlFlowInst.build_if_inst(cond)
    fail = ToUserspace.from_func_obj(cur_func)
    check_null.body.add_inst(fail)
    check_null.set_modified(InstructionColor.CHECK)
    insts.append(check_null)

    key = decl_new_var(FLOW_ID_TYPE, info, decl, FLOW_ID_VAR_NAME)
    key.set_modified()
    get_flow_id = Call(None)
    get_flow_id.name = GET_FLOW_ID
    get_flow_id.args = [sk, UnaryOp.build('&', key)]
    get_flow_id.set_modified(InstructionColor.KNOWN_FUNC_IMPL)
    insts.append(get_flow_id)
    return insts, decl, key


def prepare_shared_state_var(func):
    """
    @param func: Function the function decleration of the current function
    holding the code we are processing.
    """
    var_decl = VarDecl.build(SHARED_REF_NAME, SHARED_OBJ_PTR, red=True)
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


def prepare_sock_state_var(cur_func, info):
    from bpf_hook.skskb import SK_SKB_PROG
    assert isinstance(info.prog, SK_SKB_PROG), 'This function is only relevant to SK_SKB hook'
    insts = []
    decl = []
    ref = decl_new_var(SOCK_STATE_PTR, info, decl, name=SOCK_STATE_VAR_NAME)

    tmp_inst, tmp_decl, flow_id = skskb_get_flow_id(cur_func, info)
    decl.extend(tmp_decl)
    insts.extend(tmp_inst)

    flow_id_ref = UnaryOp.build('&', flow_id)
    tmp_inst, tmp_decl = bpf_map_lookup_elem(SOCK_STATE_MAP_NAME, flow_id_ref,
            ref, cur_func)
    insts.extend(tmp_inst)
    decl.extend(tmp_decl)

    return insts, decl


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
    ref.type = VOID_PTR
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


def new_bounded_loop(var_bound, max_bound, info, func, loop_var_type=INT,
        fail_check=False):
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
    if fail_check:
        failure_cond = BinOp.build(loop_var, '>=', max_bound)
        check_bound_failure = ControlFlowInst.build_if_inst(failure_cond)
        check_bound_failure.body.add_inst(ToUserspace.from_func_obj(func))

        failure_cond.set_modified(InstructionColor.EXTRA_ALU_OP)
        check_bound_failure.set_modified(InstructionColor.CHECK)
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
            func, UINT, fail_check=True)
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

    fail_check = max_bound != size
    tmp_insts, tmp_decl, loop_var = new_bounded_loop(size, max_bound, info,
            func, UINT, fail_check=fail_check)
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
            info, func, UINT, fail_check=True)
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
    fail_check = max_bound != size
    tmp_insts, tmp_decl, loop_var = new_bounded_loop(size, max_bound, info,
            func, UINT, fail_check=fail_check)
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
    insts = [loop]
    return insts, decl, res_var
