import json
from utility import get_tmp_var_name
from instruction import *
from data_structure import *
from parser.parse_helper import is_identifier
from helpers.bpf_ctx_helper import is_bpf_ctx_ptr
from helpers.instruction_helper import get_ret_inst


def generate_cache_lookup(inst, blk, parent_children, info):
    """
    Process an annotation of type Cache Begin

    @param inst The cache annotation instruction
    @param blk The new list of instructions we are building for current block
    @param parent_children The origin list of instructions in the parent block
    @param info

    @returns (an instruction, a list of variables to be declared at the top of function, skip_target the instructions to be skipped in this block because we have processed it here)
    """
    assert inst.kind == ANNOTATION_INST
    assert inst.ann_kind == Annotation.ANN_CACHE_BEGIN
    declare_at_top_of_func = []
    skip_target = None

    conf = json.loads(inst.msg)
    map_id = conf['id']
    assert map_id in info.map_definitions
    map_def = info.map_definitions[map_id]

    # Gather instructions between BEGIN & END
    begin = False
    on_miss = []
    # debug('Block:', parent_children)
    found_end_annotation = False
    end_conf = None
    for child in parent_children:
        if child == inst:
            # debug('*** Start gathering')
            begin = True
            continue
        if child.kind == ANNOTATION_INST and child.ann_kind == Annotation.ANN_CACHE_END:
            end_conf = json.loads(child.msg)
            assert end_conf['id'] == map_id, 'The begining and end cache id should match'
            # Notify the DFS to skip until the CACHE END
            skip_target = child
            found_end_annotation = True
            # debug('*** Stop gathering')
            break
        if not begin:
            continue
        # debug('   Gather:', child)
        on_miss.append(child)
    assert found_end_annotation, 'The end of cache block should be specified'
    assert isinstance(end_conf, dict), 'Make sure the end_conf was found'

    # Perform Lookup (Define instructions that are needed for lookup)
    map_name = map_id + '_map'
    index_name = get_tmp_var_name()
    val_ptr = get_tmp_var_name()

    lookup = []
    # Call hash function
    hash_call = Call(None)
    hash_call.name = '__fnv_hash'
    arg1 = Literal(conf['key'], CODE_LITERAL)
    arg2 = Literal(conf['key_size'], CODE_LITERAL)
    hash_call.args.extend([arg1, arg2])

    limit_inst = Literal(map_def['entries'], clang.CursorKind.INTEGER_LITERAL)
    modulo_inst = BinOp.build(hash_call, '%', limit_inst)

    # Declare variable which hold the hash value
    decl_index = VarDecl.build(index_name, BASE_TYPES[clang.TypeKind.INT])
    declare_at_top_of_func.append(decl_index)
    decl_index.update_symbol_table(info.sym_tbl)

    # Assign hash value to the variable
    ref_index = decl_index.get_ref()
    ref_assign     = BinOp.build(ref_index, '=', modulo_inst)
    lookup.append(ref_assign)

    map_lookup_call = Call(None)
    map_lookup_call.name = 'bpf_map_lookup_elem'
    arg1 = Literal(f'&{map_name}', CODE_LITERAL)
    arg2 = Literal(f'&{index_name}', CODE_LITERAL)
    map_lookup_call.args.extend([arg1, arg2])

    # Declare the variable which hold the lookup result
    decl_val_ptr = VarDecl(None)
    decl_val_ptr.name = val_ptr
    # decl_val_ptr.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
    decl_val_ptr.type = MyType.make_pointer(MyType.make_simple(map_def['value_type'], clang.TypeKind.RECORD))
    # decl_val_ptr.init.add_inst(map_lookup_call)
    declare_at_top_of_func.append(decl_val_ptr)
    decl_val_ptr.update_symbol_table(info.sym_tbl)

    # Assign lookup result to the variable
    val_ref = Ref(None)
    val_ref.name = val_ptr
    val_ref.kind = clang.CursorKind.DECL_REF_EXPR
    val_ref.type = decl_val_ptr.type
    ref_assign = BinOp.build(val_ref, '=', map_lookup_call)
    lookup.append(ref_assign)

    # Check if the value is valid
    cond = BinOp.build(val_ref, '==', Literal('NULL', clang.CursorKind.INTEGER_LITERAL))
    check_miss = ControlFlowInst.build_if_inst(cond)
    # when miss
    check_miss.body.extend_inst(on_miss)
    # when hit
    # actual_val = Literal(conf['value_ref'], CODE_LITERAL)
    # assign_ref = BinOp.build(actual_val, '=', val_ref)
    # check_miss.other_body.add_inst(assign_ref)
    template_code = end_conf['code']
    template_code = template_code.replace('%p', val_ref.name)
    template_code_inst = Literal(template_code, CODE_LITERAL)
    check_miss.other_body.add_inst(template_code_inst)
    lookup.append(check_miss)

    # TODO: I need to also run the transform_vars pass on the block of code
    # handling the cache miss (Will implement it later)

    # This should be the result of above instructions
    # f'''
    # int {index_name} = __fnv_hash({conf['key']}, {conf['key_size']});
    # void *{val_ptr}  = bpf_map_lookup_elem(&{map_name}, &{index_name});
    # if ({val_ptr} == NULL) {{
    #   {on_miss} <--- This is where cache miss is handled
    # }} else {{
    #   # instruction defined in CACHE_END
    #   # conf['value_ref'] = val_ptr;
    # }}
    # '''

    # debug('instruction for cache miss:', on_miss)

    # Mark the hash function used
    func = Function.directory['__fnv_hash']
    if not func.is_used_in_bpf_code:
        func.is_used_in_bpf_code = True
        info.prog.declarations.insert(0, func)
        debug('Add func', func.name)

    blk.extend(lookup)
    # new_inst = Block(BODY)
    # new_inst.extend_inst(lookup)
    # Replace annotation with the block of instruction we have here
    # return new_inst

    # Remove annotation
    return None, declare_at_top_of_func, skip_target


def generate_cache_update(inst, blk, current_function, info):
    """
    Process an annotation of type Cache Update

    @param inst: the annotation instruction
    @param blk: the list of instruction we are generating for current block (for
        adding some instruction before the current instruction which is being
        processed)
    @param current_function: None or an object of type Function
    @param info: the info object which has the global context of what we are doing

    @returns (an instruction, a list of variables to be declared at the top of function)
    """
    declare_at_top_of_func = []
    assert inst.kind == ANNOTATION_INST
    assert inst.ann_kind == Annotation.ANN_CACHE_BEGIN_UPDATE
    conf = json.loads(inst.msg)
    map_id = conf['id']
    def_conf = info.map_definitions[map_id]
    map_name = map_id + '_map'

    val_ref_name = get_tmp_var_name()
    index_name = get_tmp_var_name()

    value_data_type = def_conf['value_type']
    val_type = MyType.make_simple(value_data_type, clang.TypeKind.RECORD)
    val_decl = VarDecl.build(val_ref_name, MyType.make_pointer(val_type))
    declare_at_top_of_func.append(val_decl)
    val_decl.update_symbol_table(info.sym_tbl)

    decl_index = VarDecl.build(index_name, BASE_TYPES[clang.TypeKind.INT])
    declare_at_top_of_func.append(decl_index)
    decl_index.update_symbol_table(info.sym_tbl)

    insts = []
    key = Literal(conf['key'], CODE_LITERAL)
    key_size = Literal(conf['key_size'], CODE_LITERAL)

    value_annotate = conf['value']
    assert is_identifier(value_annotate), 'To check if the variable is a packet context I need to be an identifier'
    val_sym = info.sym_tbl.lookup(value_annotate)
    assert val_sym is not None, 'The variable holding the value is not found in this scope'
    value = Ref(None, clang.CursorKind.DECL_REF_EXPR)
    value.name = value_annotate
    value.type = val_sym.type
    value_size = Literal(conf['value_size'], clang.CursorKind.INTEGER_LITERAL)

    hash_call = Call(None)
    hash_call.name = '__fnv_hash'
    hash_call.args.extend([key, key_size])

    index_ref      = decl_index.get_ref()
    assign_index   = BinOp.build(index_ref, '=', hash_call)
    insts.append(assign_index)

    val_ref = val_decl.get_ref()
    map_lookup_call = Call(None)
    map_lookup_call.name = 'bpf_map_lookup_elem'
    arg1 = Literal(f'&{map_name}', CODE_LITERAL)
    arg2 = UnaryOp.build('&', index_ref)
    map_lookup_call.args.extend([arg1, arg2])
    assign_val_ref = BinOp.build(val_ref, '=', map_lookup_call)
    insts.append(assign_val_ref)

    # check if ref is not null
    null_check_cond = BinOp.build(val_ref, '!=', Literal('NULL', clang.CursorKind.INTEGER_LITERAL))
    null_check = ControlFlowInst.build_if_inst(null_check_cond)

    # Update cache
    mask_inst = BinOp.build(value_size, '&', info.prog.index_mask)
    mask_assign = BinOp.build(value_size, '=', mask_inst)
    # > Check that value size does not exceed the cache size
    sz_check_cond = BinOp.build(value_size, '>', Literal('1000', clang.CursorKind.INTEGER_LITERAL))
    sz_check = ControlFlowInst.build_if_inst(sz_check_cond)
    sz_check.body.add_inst(get_ret_inst(current_function, info))
    # > Continue by calling memcpy
    memcpy      = Call(None)
    memcpy.name = 'bpf_memcpy'
    dest_ref = val_ref.get_ref_field('data', info)
    # TODO: 1024 should be sizeof the field
    if is_bpf_ctx_ptr(dest_ref, info):
        dest_end = info.prog.get_pkt_end()
    else:
        dest_end = BinOp.build(dest_ref, '+', Literal('1024', clang.CursorKind.INTEGER_LITERAL))
        dest_end = Cast.build(dest_end, MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID]))

    if is_bpf_ctx_ptr(value, info):
        src_end = info.prog.get_pkt_end()
    else:
        tmp = BinOp.build(value, '+', value_size)
        src_end = Cast.build(tmp, MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID]))

    memcpy.args.extend([dest_ref, value, value_size, dest_end, src_end])
    size_assign = BinOp.build(val_ref.get_ref_field('size', info), '=', value_size)
    null_check.body.extend_inst([mask_assign, sz_check, memcpy, size_assign])
    insts.append(null_check)

    # map_update_call = Call(None)
    # map_update_call.name = 'bpf_map_update_elem'
    # arg1 = Literal(f'&{map_name}', CODE_LITERAL)
    # arg2 = Literal(f'&{index_name}', CODE_LITERAL)
    # arg3 = value
    # arg4 = Literal('BPF_ANY', CODE_LITERAL)
    # map_update_call.args.extend([arg1, arg2, arg3, arg4])
    # TODO: do I need to check update_elem return code?
    # insts.append(map_update_call)

    blk.extend(insts)
    return None, declare_at_top_of_func
