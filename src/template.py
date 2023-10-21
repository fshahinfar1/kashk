from instruction import *
from data_structure import *
from utility import get_tmp_var_name

VOID_PTR = 'void *'


def bpf_ctx_bound_check(ref, index, data_end):
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
    lhs_cast.cast_type = VOID_PTR

    # (void *)(data_end)
    rhs_cast = Cast()
    rhs_cast.castee.add_inst(data_end)
    rhs_cast.cast_type = VOID_PTR


    # (void *)(ref + size + 1) > (void *)(data_end)
    cond = BinOp(None)
    cond.op = '>'
    cond.lhs.add_inst(lhs_cast)
    cond.rhs.add_inst(rhs_cast)

    # return 0
    ret = Instruction()
    ret.kind = clang.CursorKind.RETURN_STMT
    ret.body = [Literal('0', kind=clang.CursorKind.INTEGER_LITERAL),]

    _if.cond.add_inst(cond)
    _if.body.add_inst(ret)

    return _if


def bpf_ctx_bound_check_bytes(ref, size, data_end):
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
    lhs_cast.cast_type = VOID_PTR

    # (void *)(ref) + size + 1
    pkt_off = BinOp(None)
    pkt_off.op = '+'
    pkt_off.lhs.add_inst(lhs_cast)
    pkt_off.rhs.add_inst(size_plus_one)

    # (void *)(data_end)
    rhs_cast = Cast()
    rhs_cast.castee.add_inst(data_end)
    rhs_cast.cast_type = VOID_PTR

    # (void *)(ref + size + 1) > (void *)(data_end)
    cond = BinOp(None)
    cond.op = '>'
    cond.lhs.add_inst(pkt_off)
    cond.rhs.add_inst(rhs_cast)

    # return 0
    ret = Instruction()
    ret.kind = clang.CursorKind.RETURN_STMT
    ret.body = [Literal('0', kind=clang.CursorKind.INTEGER_LITERAL),]

    _if.cond.add_inst(cond)
    _if.body.add_inst(ret)

    return _if

    # return '\n'.join([
    #     f'if ((void *){ref} + {size} + 1 > (void *){data_end}) {{',
    #     '  return 0;',
    #     '}\n'])


def memcpy_internal_defs():
    return '''#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif

#ifndef memmove
#define memmove(d, s, len) __builtin_memmove(d, s, len)
#endif'''


def license_text(license):
    return f'char _license[] SEC("license") = "{license}";'


def load_shared_object_code():
    return '''struct shared_state *shared = NULL;
{
  int zero = 0;
  shared = bpf_map_lookup_elem(&shared_map, &zero);
}
'''


def shared_map_decl():
    return '''struct {
  __uint(type,  BPF_MAP_TYPE_ARRAY);
  __type(key,   __u32);
  __type(value, struct shared_state);
  __uint(max_entries, 1);
} shared_map SEC(".maps");
'''


def prepare_shared_state_var():
    text = '''struct shared_state *shared = NULL;
{
  int zero = 0;
  shared = bpf_map_lookup_elem(&shared_map, &zero);
}
if (!shared) {
  return SK_DROP;
}

'''
    new_inst = Literal(text, CODE_LITERAL)
    return new_inst


def prepare_meta_data(failure_number, meta_declaration, prog):
    # TODO: use the Instruction object instead of hard coded strings
    type_name = f'struct {meta_declaration.name}'
    T = MyType.make_simple(type_name, clang.TypeKind.RECORD)
    meta_var_name = get_tmp_var_name()
    adjust_inst = prog.adjust_pkt(f'sizeof({T.spelling})')
    ctx = prog.ctx
    code = f'''
{adjust_inst}
if (((void *)(__u64){ctx}->data + sizeof({T.spelling}))  > (void *)(__u64){ctx}->data_end) {{
  return {prog.get_drop()};
}}
{T.spelling} *{meta_var_name} = (void *)(__u64){ctx}->data;
'''
    # TODO: I need to know the failure number and failure structure
    store = [f'{meta_var_name}->failure_number = {failure_number};', ]
    for f in meta_declaration.fields[1:]:
        store.append(f'{meta_var_name}->{f.name} = {f.name};')
    code += '\n'.join(store) + '\n'
    tmp = Literal(code, CODE_LITERAL)
    return tmp


def define_bpf_map(map_name, map_type, key_type, val_type, entries):
    return Literal(f'''struct {{
  __uint(type,  {map_type});
  __type(key,   {key_type});
  __type(value, {val_type});
  __uint(max_entries, {entries});
}} {map_name} SEC(".maps")
''', CODE_LITERAL)


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

    text = f'''
{{
  int zero = 0;
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
