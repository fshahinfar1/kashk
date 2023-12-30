from instruction import *
from data_structure import *
from utility import get_tmp_var_name
from helpers.bpf_ctx_helper import is_bpf_ctx_ptr
from helpers.instruction_helper import decl_new_var, ZERO, NULL, CHAR_PTR

VOID_PTR = 'void *'


def bpf_ctx_bound_check(ref, index, data_end, return_value=None):
    _if = ControlFlowInst()
    _if.kind = clang.CursorKind.IF_STMT

    # index + 1
    size_plus_one = BinOp(None)
    size_plus_one.op = '+'
    size_plus_one.lhs.add_inst(index)
    size_plus_one.rhs.add_inst(Literal('1', clang.CursorKind.INTEGER_LITERAL))

    # (ref + index + 1)
    pkt_off = BinOp(None)
    pkt_off.op = '+'
    pkt_off.lhs.add_inst(ref)
    pkt_off.rhs.add_inst(size_plus_one)

    # (void *)(ref + size + 1)
    lhs_cast = Cast()
    lhs_cast.castee.add_inst(pkt_off)
    lhs_cast.type = VOID_PTR

    # (void *)(ref + size + 1) > (void *)(data_end)
    cond = BinOp(None)
    cond.op = '>'
    cond.lhs.add_inst(lhs_cast)
    cond.rhs.add_inst(data_end)

    # return 0
    ret = Return()
    if return_value is None:
        ret.body.add_inst(Literal('0', kind=clang.CursorKind.INTEGER_LITERAL))
    else:
        ret.body.add_inst(return_value)

    _if.cond.add_inst(cond)
    _if.body.add_inst(ret)

    return _if


def bpf_ctx_bound_check_bytes(ref, size, data_end, return_value=None):
    _if = ControlFlowInst()
    _if.kind = clang.CursorKind.IF_STMT

    # size + 1
    size_plus_one = BinOp(None)
    size_plus_one.op = '+'
    size_plus_one.lhs.add_inst(size)
    size_plus_one.rhs.add_inst(Literal('1', clang.CursorKind.INTEGER_LITERAL))

    # (void *)(ref)
    lhs_cast = Cast()
    lhs_cast.castee.add_inst(ref)
    lhs_cast.type = VOID_PTR

    # (void *)(ref) + size + 1
    pkt_off = BinOp(None)
    pkt_off.op = '+'
    pkt_off.lhs.add_inst(lhs_cast)
    pkt_off.rhs.add_inst(size_plus_one)

    # (void *)(ref + size + 1) > (void *)(data_end)
    cond = BinOp(None)
    cond.op = '>'
    cond.lhs.add_inst(pkt_off)
    cond.rhs.add_inst(data_end)

    # return 0
    ret = Return()
    if return_value is None:
        ret.body.add_inst(Literal('0', kind=clang.CursorKind.INTEGER_LITERAL))
    else:
        ret.body.add_inst(return_value)

    _if.cond.add_inst(cond)
    _if.body.add_inst(ret)

    return _if

    # return '\n'.join([
    #     f'if ((void *){ref} + {size} + 1 > (void *){data_end}) {{',
    #     '  return 0;',
    #     '}\n'])


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


def prepare_shared_state_var(ret_val=None):
    SHARED_MAP_PTR = Literal('&shared_map', CODE_LITERAL)

    shared_struct = MyType.make_simple('struct shared_state',
            clang.TypeKind.RECORD)
    T = MyType.make_pointer(shared_struct)
    var_decl = VarDecl.build('shared',T)
    var_decl.init.add_inst(NULL)
    var_ref = var_decl.get_ref()

    zero_decl = VarDecl.build(get_tmp_var_name(),
            BASE_TYPES[clang.TypeKind.INT])
    zero_decl.init.add_inst(ZERO)
    zero_ref = zero_decl.get_ref()
    zero_ptr = UnaryOp.build('&', zero_ref)

    call_lookup = Call(None)
    call_lookup.name = 'bpf_map_lookup_elem'
    call_lookup.args = [SHARED_MAP_PTR, zero_ptr]

    lookup_assign = BinOp.build(var_ref, '=', call_lookup)

    cond  = BinOp.build(var_ref, '==', NULL)
    check = ControlFlowInst.build_if_inst(cond)
    if ret_val is None:
        ret_val = Return.build([])
    check.body.add_inst(ret_val)
    insts = [var_decl, zero_decl, lookup_assign,  check]
    return insts


def prepare_meta_data(failure_number, meta_declaration, info):
    type_name = f'struct {meta_declaration.name}'
    req_type = MyType.make_simple(type_name, clang.TypeKind.RECORD)
    T = MyType.make_pointer(req_type)

    target_size_inst = Literal(f'sizeof({req_type.spelling})', CODE_LITERAL)
    adjust_inst = info.prog.adjust_pkt(target_size_inst, info)

    meta_var_name = get_tmp_var_name()
    decl = VarDecl.build(meta_var_name, T)
    decl.update_symbol_table(info.sym_tbl)

    ref = decl.get_ref()
    assign = BinOp.build(ref, '=', info.prog.get_pkt_buf())

    DROP = Literal(info.prog.get_drop(), clang.CursorKind.INTEGER_LITERAL)
    ZERO = Literal('0', clang.CursorKind.INTEGER_LITERAL)
    bound_check = bpf_ctx_bound_check(ref, ZERO, info.prog.get_pkt_end(), DROP)

    store = [f'{meta_var_name}->failure_number = {failure_number};', ]
    for f in meta_declaration.fields[1:]:
        store.append(f'{meta_var_name}->{f.name} = {f.name};')
    code = '\n'.join(store) + '\n'
    populate = Literal(code, CODE_LITERAL)

    insts = adjust_inst + [decl, assign, bound_check, populate]
    return insts


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

    return [var_decl, lookup_inst], ref


def variable_memcpy(dst, src, size, up_bound, info):
    declare_at_top_of_func = []
    max_bound = Literal(str(up_bound), clang.CursorKind.INTEGER_LITERAL)
    bound_check_src = is_bpf_ctx_ptr(src, info)
    bound_check_dst = is_bpf_ctx_ptr(dst, info)

    if not hasattr(src, 'type'):
        src = Cast.build(src, CHAR_PTR)
    if not hasattr(dst, 'type'):
        dst = Cast.build(dst, CHAR_PTR)

    T = BASE_TYPES[clang.TypeKind.USHORT]
    loop_var = decl_new_var(T, info, declare_at_top_of_func)
    initialize = BinOp.build(loop_var, '=', ZERO)

    max_bound_check = BinOp.build(loop_var, '<', max_bound)
    var_bound_check = BinOp.build(loop_var, '<', size)
    condition = BinOp.build(max_bound_check, '&&', var_bound_check)

    post = UnaryOp.build('++', loop_var)
    loop = ForLoop.build(initialize, condition, post)
    loop.repeat = max_bound

    if bound_check_src:
        data_end = info.prog.get_pkt_end()
        # TODO: may return appropriate value based on function
        ret = None
        tmp_check = bpf_ctx_bound_check(src, loop_var, data_end, ret)
        loop.body.add_inst(tmp_check)

    if bound_check_dst:
        data_end = info.prog.get_pkt_end()
        # TODO: may return appropriate value based on function
        ret = None
        tmp_check = bpf_ctx_bound_check(dst, loop_var, data_end, ret)
        loop.body.add_inst(tmp_check)

    at_src = ArrayAccess.build(src, loop_var)
    at_dst = ArrayAccess.build(dst, loop_var)
    copy = BinOp.build(at_src, '=', at_dst)
    loop.body.add_inst(copy)
    return loop, declare_at_top_of_func
