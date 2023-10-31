import json
import clang.cindex as clang
from log import error, debug, report
from bpf_code_gen import gen_code
from template import (prepare_shared_state_var, define_bpf_arr_map,
        define_bpf_hash_map, malloc_lookup)
from prune import READ_PACKET, WRITE_PACKET, KNOWN_FUNCS
from utility import get_tmp_var_name, show_insts

from data_structure import *
from instruction import *
from passes.pass_obj import PassObject

from parser.parse_helper import is_identifier


MODULE_TAG = '[Transform Vars Pass]'

SEND_FLAG_NAME = '__send_flag'
FAIL_FLAG_NAME = '__fail_flag'

cb_ref = CodeBlockRef()
parent_block = CodeBlockRef()
current_function = None
# Skip until the cache END
skip_to_end = None
map_definitions = {}
declare_at_top_of_func = []


def _set_skip(val):
    global skip_to_end
    skip_to_end = val


# TODO: why I have to return functions! What am I doing? :)
def _get_ret_inst():
    ret = Instruction()
    ret.kind = clang.CursorKind.RETURN_STMT
    if current_function is None:
        ret.body = [Literal('XDP_DROP', CODE_LITERAL)]
    elif current_function.return_type.spelling != 'void':
        ret.body = [Literal(f'({current_function.return_type.spelling})0', CODE_LITERAL)]
    else:
        ret.body = []
    return ret


def _check_if_ref_is_global_state(inst, info):
    sym, scope = info.sym_tbl.lookup2(inst.name)
    is_shared = scope == info.sym_tbl.shared_scope
    if is_shared:
        # TODO: what if a variable named shared is already defined but it is
        # not our variable?
        sym = info.sym_tbl.lookup('shared')
        # debug(MODULE_TAG, 'shared symbol is defined:', sym is not None)
        if sym is None:
            # Perform a lookup on the map for globally shared values
            new_inst = prepare_shared_state_var()
            code = cb_ref.get(BODY)
            code.append(new_inst)
            T = MyType.make_simple('struct shared_state', clang.TypeKind.RECORD)
            T = MyType.make_pointer(T)
            # Update the symbol table
            # TODO: because I am not handling blocks as seperate scopes (as
            # they are). I will introduce bugs when shared is defined in an
            # inner scope.
            info.sym_tbl.insert_entry('shared', T, None, None)
    return inst


def _generate_cache_lookup(inst, info):
    """
    Process an annotation of type Cache Begin
    """
    assert inst.kind == ANNOTATION_INST
    assert inst.ann_kind == Annotation.ANN_CACHE_BEGIN
    conf = json.loads(inst.msg)
    map_id = conf['id']
    assert map_id in map_definitions
    map_def = map_definitions[map_id]

    # Gather instructions between BEGIN & END
    begin = False
    on_miss = []
    blk = cb_ref.get(BODY)
    parent_node = parent_block.get(BODY)
    parent_children = parent_node.get_children()
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
            _set_skip(child)
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
    modulo_inst = BinOp.build_op(hash_call, '%', limit_inst)

    # Declare variable which hold the hash value
    decl_index = VarDecl(None)
    decl_index.name = index_name
    decl_index.type = BASE_TYPES[clang.TypeKind.INT]
    declare_at_top_of_func.append(decl_index)
    decl_index.update_symbol_table(info.sym_tbl)

    # Assign hash value to the variable
    ref_index = Ref(None, clang.CursorKind.DECL_REF_EXPR)
    ref_index.name = decl_index.name
    ref_index.type = decl_index.type
    ref_assign     = BinOp.build_op(ref_index, '=', modulo_inst)
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
    ref_assign = BinOp.build_op(val_ref, '=', map_lookup_call)
    lookup.append(ref_assign)

    # Check if the value is valid
    cond = BinOp.build_op(val_ref, '==', Literal('NULL', clang.CursorKind.INTEGER_LITERAL))
    check_miss = ControlFlowInst.build_if_inst(cond)
    # when miss
    check_miss.body.extend_inst(on_miss)
    # when hit
    # actual_val = Literal(conf['value_ref'], CODE_LITERAL)
    # assign_ref = BinOp.build_op(actual_val, '=', val_ref)
    # check_miss.other_body.add_inst(assign_ref)
    template_code = end_conf['code']
    template_code = template_code.replace('%p', val_ref.name)
    template_code_inst = Literal(template_code, CODE_LITERAL)
    check_miss.other_body.add_inst(template_code_inst)
    lookup.append(check_miss)

    # TODO: I need to also run the transform_vars pass on the block of code
    # handling the cache miss (Will implement it later)

    # This should be the result of above instructions
    f'''
    int {index_name} = __fnv_hash({conf['key']}, {conf['key_size']});
    void *{val_ptr}  = bpf_map_lookup_elem(&{map_name}, &{index_name});
    if ({val_ptr} == NULL) {{
      {on_miss} <--- This is where cache miss is handled
    }} else {{
      # instruction defined in CACHE_END
      # conf['value_ref'] = val_ptr;
    }}
    '''

    # debug(MODULE_TAG, 'instruction for cache miss:', on_miss)

    # Mark the hash function used
    func = Function.directory['__fnv_hash']
    if not func.is_used_in_bpf_code:
        func.is_used_in_bpf_code = True
        info.prog.declarations.insert(0, func)
        debug(MODULE_TAG, 'Add func', func.name)

    blk.extend(lookup)
    # new_inst = Block(BODY)
    # new_inst.extend_inst(lookup)
    # Replace annotation with the block of instruction we have here
    # return new_inst

    # Remove annotation
    return None


def _generate_cache_update(inst, info):
    """
    Process an annotation of type Cache Update
    """
    assert inst.kind == ANNOTATION_INST
    assert inst.ann_kind == Annotation.ANN_CACHE_BEGIN_UPDATE
    conf = json.loads(inst.msg)
    map_id = conf['id']
    def_conf = map_definitions[map_id]
    map_name = map_id + '_map'

    val_ref_name = get_tmp_var_name()
    index_name = get_tmp_var_name()

    value_data_type = def_conf['value_type']
    print(value_data_type)
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
    assign_index   = BinOp.build_op(index_ref, '=', hash_call)
    insts.append(assign_index)

    val_ref = val_decl.get_ref()
    map_lookup_call = Call(None)
    map_lookup_call.name = 'bpf_map_lookup_elem'
    arg1 = Literal(f'&{map_name}', CODE_LITERAL)
    arg2 = UnaryOp.build('&', index_ref)
    map_lookup_call.args.extend([arg1, arg2])
    assign_val_ref = BinOp.build_op(val_ref, '=', map_lookup_call)
    insts.append(assign_val_ref)

    # check if ref is not null
    null_check_cond = BinOp.build_op(val_ref, '!=', Literal('NULL', clang.CursorKind.INTEGER_LITERAL))
    null_check = ControlFlowInst.build_if_inst(null_check_cond)

    # Update cache
    mask_inst = BinOp.build_op(value_size, '&', Literal('PKT_OFFSET_MASK', clang.CursorKind.MACRO_INSTANTIATION))
    mask_assign = BinOp.build_op(value_size, '=', mask_inst)
    # > Check that value size does not exceed the cache size
    sz_check_cond = BinOp.build_op(value_size, '>', Literal('1000', clang.CursorKind.INTEGER_LITERAL))
    sz_check = ControlFlowInst.build_if_inst(sz_check_cond)
    sz_check.body.add_inst(_get_ret_inst())
    # > Continue by calling memcpy
    memcpy      = Call(None)
    memcpy.name = 'bpf_memcpy'
    dest_ref = val_ref.get_ref_field('data')
    # TODO: 1024 should be sizeof the field
    dest_end = BinOp.build_op(dest_ref, '+', Literal('1024', clang.CursorKind.INTEGER_LITERAL))
    dest_end = Cast.build(dest_end, MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID]))
    tmp = BinOp.build_op(value, '+', value_size)
    src_end = Cast.build(tmp, MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID]))
    memcpy.args.extend([dest_ref, value, value_size, dest_end, src_end])
    size_assign = BinOp.build_op(val_ref.get_ref_field('size'), '=', value_size)
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

    blk = cb_ref.get(BODY)
    blk.extend(insts)
    return None


def _process_annotation(inst, info):
    if inst.ann_kind == Annotation.ANN_CACNE_DEFINE:
        conf = json.loads(inst.msg)
        map_id   = conf['id']
        map_name = map_id  + '_map'
        val_type = conf['value_type']
        # TODO: get the map size from the annotation
        conf['entries'] = '1024'
        entries = conf['entries']
        m = define_bpf_arr_map(map_name, val_type, entries)

        # check if value was defined before
        for d in info.prog.declarations:
            if isinstance(d, TypeDefinition) and d.name == val_type:
                # Found the type
                break
        else:
            # The value type is not declared yet
            from passes.mark_used_funcs import _add_type_to_declarations
            T = MyType.make_simple(val_type, clang.TypeKind.RECORD)
            _add_type_to_declarations(T, info)

        info.prog.add_declaration(m)
        map_definitions[map_id] = conf
        report('Declare map', m, 'for malloc')
    elif inst.ann_kind == Annotation.ANN_CACHE_END:
        # Nothing to do
        pass
    elif inst.ann_kind == Annotation.ANN_CACHE_BEGIN:
        return _generate_cache_lookup(inst, info)
    elif inst.ann_kind == Annotation.ANN_CACHE_BEGIN_UPDATE:
        return _generate_cache_update(inst, info)
    elif inst.ann_kind == Annotation.ANN_CACHE_END_UPDATE:
        # TODO: do I want to have some code after update ??
        pass
    # Remove annotation
    return None


def _process_read_call(inst, info):
    blk = cb_ref.get(BODY)

    # NOTE: I can assign the pointer but then the buffer size won't be right? <-- should be looked at as an optimization?
    report('Assigning packet buffer to var:', inst.rd_buf.name)
    # Assign packet pointer on a previouse line
    lhs = inst.rd_buf.ref
    rhs = info.prog.get_pkt_buf()
    assign_inst = BinOp.build_op(lhs, '=', rhs)
    blk.append(assign_inst)
    # TODO: what if `skb` is not defined in this scope?
    # Set the return value
    inst = info.prog.get_pkt_size()

    # sz_decl = VarDecl.build(get_tmp_var_name(), BASE_TYPES[clang.TypeKind.USHORT])
    # declare_at_top_of_func.append(sz_decl)
    # sz_ref  = sz_decl.get_ref()
    # sz_assign  = BinOp.build_op(sz_ref, '=', info.prog.get_pkt_size())
    # blk.append(sz_assign)
    # sz_mask = BinOp.build_op(sz_ref, '&', Literal('PKT_OFFSET_MASK', clang.CursorKind.MACRO_INSTANTIATION))
    # sz_assign_mask = BinOp.build_op(sz_ref, '=', sz_mask)
    # blk.append(sz_assign_mask)

    # # check size is less than map buffer size
    # size_check_cond = BinOp.build_op(sz_ref, '>', Literal('1000', clang.CursorKind.INTEGER_LITERAL))
    # size_check = ControlFlowInst.build_if_inst(size_check_cond)
    # size_check.body.add_inst(_get_ret_inst())
    # blk.append(size_check)


    # # Copy data from XDP to Buffer
    # lhs = Literal(inst.rd_buf.name, CODE_LITERAL)
    # rhs = info.prog.get_pkt_buf()
    # # TODO: check if context is used
    # # dst_end = Literal('<not set>', CODE_LITERAL)
    # # TODO: cast lhs to void *
    # dst_end = BinOp.build_op(lhs, '+', Literal(inst.rd_buf.size_cursor, CODE_LITERAL))
    # src_end = info.prog.get_pkt_end()
    # cpy = Call(None)
    # cpy.name = 'bpf_memcpy'
    # cpy.args = [lhs, rhs, sz_ref, dst_end, src_end]
    # blk.append(cpy)

    # # Mark memcpy as used
    # func = cpy.get_function_def()
    # assert func is not None
    # if not func.is_used_in_bpf_code:
    #     func.is_used_in_bpf_code = True
    #     info.prog.declarations.insert(0, func)
    #     # debug(MODULE_TAG, 'Add func', func.name)

    # inst = sz_ref
    return inst


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.DECL_REF_EXPR:
        return _check_if_ref_is_global_state(inst, info)
    elif inst.kind == clang.CursorKind.VAR_DECL:
        # TODO: I might want to remove some variable declarations here
        # e.g., ones related to reading/writing responses
        pass
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        if inst.name in READ_PACKET:
            return _process_read_call(inst, info)
        elif inst.name in WRITE_PACKET:
            # Let's not transform the send right now, wait for
            # verifier to determine which variables are pointing to the context.
            # return _process_write_call(inst, info)
            return inst
        elif inst.name in KNOWN_FUNCS:
            return inst
        else:
            # Check if the function being invoked needs to receive any flag and pass.
            func = inst.get_function_def()
            if not func:
                return inst
            if (func.calls_recv  or func.calls_send) and (inst.change_applied & Function.CTX_FLAG == 0):
                inst.change_applied |= Function.CTX_FLAG
                ctx_ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
                ctx_ref.name = info.prog.ctx
                ctx_ref.type = info.prog.ctx_type
                inst.args.append(ctx_ref)

            if func.calls_send and (inst.change_applied & Function.SEND_FLAG == 0):
                inst.change_applied |= Function.SEND_FLAG
                if current_function is None:
                    # Allocate the flag on the stack and pass a poitner
                    decl = VarDecl(None)
                    decl.name = SEND_FLAG_NAME
                    decl.type = BASE_TYPES[clang.TypeKind.SCHAR]
                    decl.init.add_inst(Literal('0', clang.CursorKind.INTEGER_LITERAL))
                    blk = cb_ref.get(BODY)
                    blk.append(decl)
                    info.sym_tbl.insert_entry(decl.name, decl.type, decl.kind, None)

                    flag_ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
                    flag_ref.name = SEND_FLAG_NAME
                    flag_ref.type = BASE_TYPES[clang.TypeKind.SCHAR]

                    ref = UnaryOp.build('&', flag_ref)
                    inst.args.append(ref)
                else:
                    # Just pass the reference
                    flag_ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
                    flag_ref.name = SEND_FLAG_NAME
                    flag_ref.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
                    inst.args.append(flag_ref)
    elif inst.kind == ANNOTATION_INST:
        return _process_annotation(inst, info)
    return inst


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
    new_children = []

    with cb_ref.new_ref(ctx, parent_list):
        # Process current instruction
        inst = _process_current_inst(inst, info, more)
        if inst is None:
            # debug(MODULE_TAG, 'remove instruction:', inst)
            return None
        # Continue deeper
        gather = False
        for child, tag in inst.get_children_context_marked():
            is_list = isinstance(child, list)
            if not is_list:
                child = [child]
            new_child = []

            # TODO: is there no other/better way for doing BFS in middle of DFS?
            with parent_block.new_ref(tag, inst):
                for i in child:
                    # Check if we are skipping
                    if skip_to_end is not None:
                        if skip_to_end == i:
                            _set_skip(None)
                        continue

                    obj = PassObject.pack(lvl+1, tag, new_child)
                    new_inst = _do_pass(i, info, obj)
                    if new_inst is None:
                        continue
                    new_child.append(new_inst)
            if not is_list:
                if len(new_child) < 1:
                    # debug(MODULE_TAG, 'remove instruction:', inst)
                    return None
                assert len(new_child) == 1, f'expect to receive one object (count = {len(new_child)})'
                new_child = new_child[-1]
            new_children.append(new_child)
    new_inst = inst.clone(new_children)
    return new_inst


def _check_func_receives_all_the_flags(func, info):
    """
    Check if function receives flags it need through its arguments
    """
    if (func.calls_send or func.calls_recv) and (func.change_applied & Function.CTX_FLAG == 0):
        # Add the BPF context to its arguemt
        arg = StateObject(None)
        arg.name = info.prog.ctx
        arg.type_ref = info.prog.ctx_type
        func.args.append(arg)
        func.change_applied |= Function.CTX_FLAG
        scope = info.sym_tbl.scope_mapping.get(func.name)
        assert scope is not None
        scope.insert_entry(arg.name, arg.type_ref, clang.CursorKind.PARM_DECL, None)

    if func.calls_send and (func.change_applied & Function.SEND_FLAG == 0):
        # Add the send flag
        arg = StateObject(None)
        arg.name = SEND_FLAG_NAME
        arg.type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
        func.args.append(arg)
        func.change_applied |= Function.SEND_FLAG
        scope = info.sym_tbl.scope_mapping.get(func.name)
        assert scope is not None
        scope.insert_entry(arg.name, arg.type_ref, clang.CursorKind.PARM_DECL, None)

    if func.may_succeed and func.may_fail and (func.change_applied & Function.FAIL_FLAG == 0):
        arg = StateObject(None)
        arg.name = FAIL_FLAG_NAME
        arg.type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
        func.args.append(arg)
        func.change_applied |= Function.FAIL_FLAG
        scope = info.sym_tbl.scope_mapping.get(func.name)
        assert scope is not None
        scope.insert_entry(arg.name, arg.type_ref, clang.CursorKind.PARM_DECL, None)
        # debug('add param:', FAIL_FLAG_NAME, 'to', func.name)


def transform_vars_pass(inst, info, more):
    """
    Transformations in this pass

    * Global variables
    * Read/Recv instruction
    * Write/Send instructions
    * Known function substitution
    * Cache Generation
    """
    global current_function
    current_function = None
    res = _do_pass(inst, info, more)
    if declare_at_top_of_func:
        for inst in declare_at_top_of_func:
            res.children.insert(0, inst)
    declare_at_top_of_func.clear()

    for func in Function.directory.values():
        if func.is_used_in_bpf_code:
            current_function = func
            with info.sym_tbl.with_func_scope(current_function.name):
                _check_func_receives_all_the_flags(func, info)
                func.body = _do_pass(func.body, info, PassObject())
                if declare_at_top_of_func:
                    for inst in declare_at_top_of_func:
                        func.body.children.insert(0, inst)
                declare_at_top_of_func.clear()
            current_function = None
    return res
