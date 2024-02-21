import json
from utility import get_tmp_var_name
from instruction import *
from data_structure import *
from parser.parse_helper import is_identifier
from helpers.bpf_ctx_helper import is_bpf_ctx_ptr
from helpers.instruction_helper import (get_ret_inst, decl_new_var, ZERO, ONE)
import template

TAG = '[Cache Helper]'


def get_ref_from_name(name, info):
    tmp_sym = info.sym_tbl.lookup(name)
    if tmp_sym is None:
        raise Exception('Name passed to the cache annotation needs to be a valid variable name')
    ref = Ref.from_sym(tmp_sym)
    return ref


def get_var_end(var, upper_bound_inst, info):
    if is_bpf_ctx_ptr(var, info):
        end = info.prog.get_pkt_end()
    else:
        end = BinOp.build(var, '+', upper_bound_inst)
        end = Cast.build(end, BASE_TYPES[VOID_PTR])
    return end


def gen_memcpy(info, current_function, dst, src, size, upper_bound):
    ret = get_ret_inst(current_function, info)
    ret_val = None
    if len(ret.body.children) > 0:
        ret_val = ret.body.children[0]
    return template.variable_memcpy(dst, src, size, upper_bound, info, ret_val)


def get_map_name(map_id):
    return map_id + '_map'


def generate_cache_lookup(inst, blk, parent_children, info):
    """
    Process an annotation of type Cache Begin

    @param inst The cache annotation instruction
    @param blk The new list of instructions we are building for current block
    @param parent_children The origin list of instructions in the parent block
    @param info

    @returns (an instruction, a list of variables to be declared at the top of
    function, skip_target the instructions to be skipped in this block because
    we have processed it here)
    """
    assert inst.kind == ANNOTATION_INST
    assert inst.ann_kind == Annotation.ANN_CACHE_BEGIN
    declare_at_top_of_func = []

    conf = json.loads(inst.msg)
    map_id = conf['id']
    assert map_id in info.map_definitions
    map_def = info.map_definitions[map_id]

    on_miss = inst.block.get_children()
    end_ann_inst = parent_children[parent_children.index(inst) + 1]
    end_conf = json.loads(end_ann_inst.msg)
    assert end_conf['id'] == map_id, 'The begining and end cache id should match'

    # Perform Lookup (Define instructions that are needed for lookup)
    map_name = get_map_name(map_id)

    lookup = []
    # Call hash function
    hash_call = Call(None)
    hash_call.name = '__fnv_hash'
    # Check if key variable name is valid
    # key = Literal(conf['key'], CODE_LITERAL)
    key = get_ref_from_name(conf['key'], info)
    key_size = Literal(conf['key_size'], CODE_LITERAL)
    arg3 = get_var_end(key, key_size, info)
    hash_call.args.extend([key, key_size, arg3])

    limit_inst = Literal(map_def['entries'], clang.CursorKind.INTEGER_LITERAL)
    modulo_inst = BinOp.build(hash_call, '%', limit_inst)

    # Assign hash value to the variable
    ref_index = decl_new_var(BASE_TYPES[clang.TypeKind.INT],
            info, declare_at_top_of_func)
    ref_assign = BinOp.build(ref_index, '=', modulo_inst)
    lookup.append(ref_assign)

    map_lookup_call = Call(None)
    map_lookup_call.name = 'bpf_map_lookup_elem'
    # arg1 = UnaryOp.build('&', map_name)
    arg1 = Literal(f'&{map_name}', CODE_LITERAL)
    arg2 = UnaryOp.build('&', ref_index)
    map_lookup_call.args.extend([arg1, arg2])

    # Assign lookup result to the variable
    VALUE_TYPE = MyType.make_simple(map_def['value_type'], clang.TypeKind.RECORD)
    VALUE_TYPE_PTR = MyType.make_pointer(VALUE_TYPE)
    val_ref = decl_new_var(VALUE_TYPE_PTR, info, declare_at_top_of_func)
    ref_assign = BinOp.build(val_ref, '=', map_lookup_call)
    lookup.append(ref_assign)

    # Create hit flag
    miss_flag = decl_new_var(BASE_TYPES[clang.TypeKind.INT], info,
            declare_at_top_of_func)
    miss_flag_init = BinOp.build(miss_flag, '=', ONE)
    lookup.append(miss_flag_init)

    # Check if the value is valid
    cond = BinOp.build(val_ref, '!=', Literal('NULL', clang.CursorKind.INTEGER_LITERAL))
    check = ControlFlowInst.build_if_inst(cond)
    # check key sizes match
    key_size_field = val_ref.get_ref_field('key_size', info)
    check_key_len_cond = BinOp.build(key_size_field, '==', key_size)
    check_key_len = ControlFlowInst.build_if_inst(check_key_len_cond)
    check.body.add_inst(check_key_len)
    key_field = val_ref.get_ref_field('key', info)
    # TODO: 16 is the max key size which should be determined based on the
    # internal cache data strucutre
    tmp_insts, tmp_decl, tmp_cmp_res = template.strncmp(key_field, key,
            key_size, 255, info)
    declare_at_top_of_func.extend(tmp_decl)
    check_key_len.body.extend_inst(tmp_insts)

    key_check_cond = BinOp.build(tmp_cmp_res, '==', ZERO)
    key_check = ControlFlowInst.build_if_inst(key_check_cond)
    check_key_len.body.add_inst(key_check)
    # when hit
    template_code = end_conf['code']
    template_code = template_code.replace('%p', val_ref.name)
    template_code_inst = Literal(template_code, CODE_LITERAL)
    unset_miss_flag = BinOp.build(miss_flag, '=', ZERO)
    key_check.body.extend_inst([template_code_inst, unset_miss_flag])
    lookup.append(check)
    # Check if miss flag is set (ON_MISS)
    miss_flag_check = ControlFlowInst.build_if_inst(miss_flag)
    miss_flag_check.body.extend_inst(on_miss)
    lookup.append(miss_flag_check)

    if HASH_HELPER_HEADER not in info.prog.headers:
        info.prog.headers.append(HASH_HELPER_HEADER)

    blk.extend(lookup)
    # Remove annotation
    return None, declare_at_top_of_func


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
    map_name = get_map_name(map_id)

    val_ref_name = get_tmp_var_name()
    index_name = get_tmp_var_name()

    # This should be the internal caching data type
    value_data_type = def_conf['value_type']
    val_type = MyType.make_simple(value_data_type, clang.TypeKind.RECORD)
    val_decl = VarDecl.build(val_ref_name, MyType.make_pointer(val_type))
    declare_at_top_of_func.append(val_decl)
    val_decl.update_symbol_table(info.sym_tbl)

    decl_index = VarDecl.build(index_name, BASE_TYPES[clang.TypeKind.INT])
    declare_at_top_of_func.append(decl_index)
    decl_index.update_symbol_table(info.sym_tbl)

    insts = []
    # key = Literal(conf['key'], CODE_LITERAL)
    key = get_ref_from_name(conf['key'], info)
    key_size = Literal(conf['key_size'], CODE_LITERAL)
    key_end  = get_var_end(key, key_size, info)

    value_var_name = conf['value']
    assert is_identifier(value_var_name), 'To check if the variable is a packet context I need to be an identifier'
    value = get_ref_from_name(value_var_name, info)
    value_size = Literal(conf['value_size'], clang.CursorKind.INTEGER_LITERAL)

    hash_call = Call(None)
    hash_call.name = '__fnv_hash'
    hash_call.args.extend([key, key_size, key_end])

    limit_inst = Literal(def_conf['entries'], clang.CursorKind.INTEGER_LITERAL)
    modulo_inst = BinOp.build(hash_call, '%', limit_inst)

    index_ref      = decl_index.get_ref()
    assign_index   = BinOp.build(index_ref, '=', modulo_inst)
    insts.append(assign_index)

    item_ref = val_decl.get_ref()
    map_lookup_call = Call(None)
    map_lookup_call.name = 'bpf_map_lookup_elem'
    arg1 = Literal(f'&{map_name}', CODE_LITERAL)
    arg2 = UnaryOp.build('&', index_ref)
    map_lookup_call.args.extend([arg1, arg2])
    assign_val_ref = BinOp.build(item_ref, '=', map_lookup_call)
    insts.append(assign_val_ref)

    # check if ref is not null
    null_check_cond = BinOp.build(item_ref, '!=', Literal('NULL', clang.CursorKind.INTEGER_LITERAL))
    null_check = ControlFlowInst.build_if_inst(null_check_cond)

    # Update cache
    ## rewrite key
    dest_ref = item_ref.get_ref_field('key', info)
    cpy, decl, ret = gen_memcpy(info, current_function,
            dest_ref, key, key_size, upper_bound='255')
    declare_at_top_of_func.extend(decl)
    null_check.body.add_inst(cpy)
    key_size_field = item_ref.get_ref_field('key_size', info)
    size_assign = BinOp.build(key_size_field, '=', key_size)
    null_check.body.add_inst(size_assign)
    ## rewrite value
    dest_ref = item_ref.get_ref_field('value', info)
    cpy, decl, ret = gen_memcpy(info, current_function,
            dest_ref, value, value_size, upper_bound='255')
    declare_at_top_of_func.extend(decl)
    null_check.body.add_inst(cpy)
    size_assign = BinOp.build(item_ref.get_ref_field('value_size', info), '=', value_size)
    null_check.body.add_inst(size_assign)
    insts.append(null_check)
    blk.extend(insts)
    return None, declare_at_top_of_func
