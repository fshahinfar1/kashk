import json
from utility import get_tmp_var_name
from instruction import *
from data_structure import *
from my_type import MyType
from parser.parse_helper import is_identifier
from helpers.bpf_ctx_helper import is_bpf_ctx_ptr
from helpers.instruction_helper import (get_ret_inst, decl_new_var, ZERO, ONE,
        CHAR, UINT, VOID, NULL)
import template
from passes.update_original_ref import set_original_ref
from var_names import (CACHE_SIZE, CACHE_ITEM_STRUCT_NAME, CACHE_KEY_MAX_SIZE,
        CACHE_VALUE_MAX_SIZE)


TAG = '[Cache Helper]'
INTERNAL_CACHE_ELEMENT_STRUCT = MyType.make_simple(f'struct {CACHE_ITEM_STRUCT_NAME}',
        clang.TypeKind.RECORD)


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


def get_ret_val(current_function, info):
    ret = get_ret_inst(current_function, info)
    ret_val = None
    if len(ret.body.children) > 0:
        ret_val = ret.body.children[0]
    return ret_val


def gen_memcpy(info, current_function, dst, src, size, upper_bound):
    return template.variable_memcpy(dst, src, size, upper_bound, info, current_function)


def get_map_name(map_id):
    return map_id + '_map'


def generate_cache_lookup(inst, blk, current_function, parent_children, info):
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
    hash_call.set_modified(InstructionColor.KNOWN_FUNC_IMPL)

    limit_inst = Literal(map_def['entries'], clang.CursorKind.INTEGER_LITERAL)
    modulo_inst = BinOp.build(hash_call, '%', limit_inst)
    modulo_inst.set_modified(InstructionColor.EXTRA_ALU_OP)

    # Assign hash value to the variable
    ref_index = decl_new_var(BASE_TYPES[clang.TypeKind.INT],
            info, declare_at_top_of_func)
    ref_assign = BinOp.build(ref_index, '=', modulo_inst)
    ref_assign.set_modified()
    lookup.append(ref_assign)

    map_lookup_call = Call(None)
    map_lookup_call.name = 'bpf_map_lookup_elem'
    # arg1 = UnaryOp.build('&', map_name)
    tmp_map_type = MyType.make_simple(map_name, clang.TypeKind.RECORD)
    map_ref = UnaryOp.build('&', Ref.build(map_name, tmp_map_type))
    arg1 = map_ref
    arg2 = UnaryOp.build('&', ref_index)
    map_lookup_call.args.extend([arg1, arg2])
    map_lookup_call.set_modified(InstructionColor.MAP_LOOKUP)

    # Assign lookup result to the variable
    VALUE_TYPE = MyType.make_simple(map_def['value_type'], clang.TypeKind.RECORD)
    VALUE_TYPE_PTR = MyType.make_pointer(VALUE_TYPE)
    val_ref = decl_new_var(VALUE_TYPE_PTR, info, declare_at_top_of_func)
    ref_assign = BinOp.build(val_ref, '=', map_lookup_call)
    lookup.append(ref_assign)
    ref_assign.set_modified()

    # Create hit flag
    miss_flag = decl_new_var(BASE_TYPES[clang.TypeKind.INT], info,
            declare_at_top_of_func)
    miss_flag_init = BinOp.build(miss_flag, '=', ONE)
    lookup.append(miss_flag_init)
    miss_flag.set_modified()
    miss_flag_init.set_modified()

    # Check if the value is valid
    cond = BinOp.build(val_ref, '!=', NULL)
    check = ControlFlowInst.build_if_inst(cond)
    check.set_modified(InstructionColor.CHECK)

    # check key sizes match
    key_size_field = val_ref.get_ref_field('key_size', info)
    check_key_len_cond = BinOp.build(key_size_field, '==', key_size)
    check_key_len_cond.set_modified(InstructionColor.EXTRA_ALU_OP)
    check_key_len = ControlFlowInst.build_if_inst(check_key_len_cond)
    check_key_len.set_modified(InstructionColor.CHECK)
    check.body.add_inst(check_key_len)
    key_field = val_ref.get_ref_field('key', info)
    tmp_insts, tmp_decl, tmp_cmp_res = template.strncmp(key_field, key,
            key_size, CACHE_KEY_MAX_SIZE, info, current_function)
    declare_at_top_of_func.extend(tmp_decl)
    check_key_len.body.extend_inst(tmp_insts)

    key_check_cond = BinOp.build(tmp_cmp_res, '==', ZERO)
    key_check_cond.set_modified(InstructionColor.EXTRA_ALU_OP)
    key_check = ControlFlowInst.build_if_inst(key_check_cond)
    key_check.set_modified(InstructionColor.CHECK)
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
    miss_flag_check.set_modified(InstructionColor.CHECK)
    lookup.append(miss_flag_check)

    if HASH_HELPER_HEADER not in info.prog.headers:
        info.prog.headers.append(HASH_HELPER_HEADER)

    blk.extend(lookup)
    set_original_ref(lookup, info, inst.original)
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
    tmp_map_type = MyType.make_simple(map_name, clang.TypeKind.RECORD)
    map_ref = UnaryOp.build('&', Ref.build(map_name, tmp_map_type))
    arg1 = map_ref
    arg2 = UnaryOp.build('&', index_ref)
    map_lookup_call.args.extend([arg1, arg2])
    assign_val_ref = BinOp.build(item_ref, '=', map_lookup_call)
    insts.append(assign_val_ref)

    # check if ref is not null
    null_check_cond = BinOp.build(item_ref, '!=', NULL)
    null_check = ControlFlowInst.build_if_inst(null_check_cond)

    # Update cache
    ## rewrite key
    dest_ref = item_ref.get_ref_field('key', info)
    cpy, decl, ret = gen_memcpy(info, current_function,
            dest_ref, key, key_size, upper_bound=CACHE_KEY_MAX_SIZE)
    declare_at_top_of_func.extend(decl)
    null_check.body.extend_inst(cpy)
    key_size_field = item_ref.get_ref_field('key_size', info)
    size_assign = BinOp.build(key_size_field, '=', key_size)
    null_check.body.add_inst(size_assign)
    ## rewrite value
    dest_ref = item_ref.get_ref_field('value', info)
    cpy, decl, ret = gen_memcpy(info, current_function,
            dest_ref, value, value_size, upper_bound=CACHE_VALUE_MAX_SIZE)
    declare_at_top_of_func.extend(decl)
    null_check.body.extend_inst(cpy)
    size_assign = BinOp.build(item_ref.get_ref_field('value_size', info), '=', value_size)
    null_check.body.add_inst(size_assign)

    null_check.set_modified(InstructionColor.CHECK)

    insts.append(null_check)
    blk.extend(insts)
    set_original_ref(insts, info, inst.original)
    return None, declare_at_top_of_func


def declare_cache_item_if_needed(info):
    # Check if internal cache item is declared
    tmp_decl = MyType.type_table.get(CACHE_ITEM_STRUCT_NAME)
    if tmp_decl is not None:
        return
    key_type = MyType.make_array('_not_set_1', CHAR, CACHE_KEY_MAX_SIZE)
    val_type = MyType.make_array('_not_set_2', CHAR, CACHE_VALUE_MAX_SIZE)
    fields = [
            StateObject.build('key', key_type),
            StateObject.build('key_size', UINT),
            StateObject.build('value', val_type),
            StateObject.build('value_size', UINT),
            ]
    decl = Record(CACHE_ITEM_STRUCT_NAME, fields)
    decl.is_used_in_bpf_code = True
     
    gs = info.sym_tbl.global_scope
    with info.sym_tbl.with_scope(gs):
        decl.update_symbol_table(info.sym_tbl)
    return decl


def define_internal_cache(inst, info):
    assert isinstance(inst, Annotation)
    assert inst.ann_kind == Annotation.ANN_CACNE_DEFINE

    type_decl = []

    conf = json.loads(inst.msg)
    map_id   = conf['id']
    map_name = map_id  + '_map'
    # TODO: it is an internal cache object type
    conf['value_type'] = INTERNAL_CACHE_ELEMENT_STRUCT.spelling
    val_type = conf['value_type']
    # TODO: get the map size from the annotation
    conf['entries'] = str(CACHE_SIZE)
    entries = int(conf['entries'])

    tmp = declare_cache_item_if_needed(info)
    type_decl.append(tmp)

    m = BPFMap.build_arr_map(map_name, INTERNAL_CACHE_ELEMENT_STRUCT, entries)
    m.is_used_in_bpf_code = True
    type_decl.append(m)
    
    return type_decl, conf
