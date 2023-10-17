import json
import clang.cindex as clang
from log import error, debug, report
from bpf_code_gen import gen_code
from template import prepare_shared_state_var, define_bpf_arr_map, malloc_lookup
from prune import READ_PACKET, WRITE_PACKET, KNOWN_FUNCS
from utility import get_tmp_var_name

from data_structure import *
from instruction import *
from passes.pass_obj import PassObject


MODULE_TAG = '[Transform Vars Pass]'

SEND_FLAG_NAME = '__send_flag'
FAIL_FLAG_NAME = '__fail_flag'

cb_ref = CodeBlockRef()
parent_block = CodeBlockRef()
current_function = None
# Skip until the cache END
skip_to_end = None


def _set_skip(val):
    global skip_to_end
    skip_to_end = val


def _get_fail_ret_val():
    if current_function is None:
        return 'XDP_DROP'
    elif current_function.return_type.spelling == 'void':
        return ''
    else:
        return f'({current_function.return_type.spelling})0'

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


_malloc_map_counter = 0
def _get_malloc_name():
    global _malloc_map_counter
    _malloc_map_counter += 1
    return f'malloc_{_malloc_map_counter}'


def _known_function_substitution(inst, info):
    """
    Replace some famous functions with implementations that work in BPF
    """
    if inst.name == 'strlen':
        inst.name = 'bpf_strlen'
        # Mark the function used
        func = inst.get_function_def()
        assert func is not None
        func.is_used_in_bpf_code = True
        info.prog.declarations.insert(0, func)
        # TODO: Also do a check if the return value is valid (check the size limit)
        return inst
    elif inst.name == 'malloc':
        map_value_size,_ = gen_code([inst.args[0]], info)
        name = _get_malloc_name()
        map_name = name + '_map'

        # Define structure which will be the value of the malloc map
        field = StateObject(None)
        field.name = 'data'
        field.type_ref = MyType.make_array('_unset_type_name_', BASE_TYPES[clang.TypeKind.SCHAR], map_value_size)
        value_type = Record(name, [field])
        value_type.is_used_in_bpf_code = True
        info.prog.add_declaration(value_type)
        report('Declare', value_type, 'as malloc object')

        # Define the map
        m = define_bpf_arr_map(map_name, f'struct {name}', 1)
        info.prog.add_declaration(m)
        report('Declare map', m, 'for malloc')

        # Look the malloc map
        return_val = _get_fail_ret_val()
        lookup_inst, ref = malloc_lookup(name, info, return_val)
        blk = cb_ref.get(BODY)
        blk.append(lookup_inst)
        return ref
    error(f'Know function {inst.name} is not implemented yet')
    return inst


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


def _process_annotation(inst, info):
    if inst.ann_kind == Annotation.ANN_CACNE_DEFINE:
        conf = json.loads(inst.msg)
        map_name = conf['id'] + '_map'
        val_type = conf['value_type']
        m = define_bpf_arr_map(map_name, val_type, 1)
        info.prog.add_declaration(m)
        report('Declare map', m, 'for malloc')
    elif inst.ann_kind == Annotation.ANN_CACHE_END:
        # Nothing to do
        pass
    elif inst.ann_kind == Annotation.ANN_CACHE_BEGIN:
        conf = json.loads(inst.msg)

        # Gather instructions between BEGIN & END
        begin = False
        on_miss = []
        blk = cb_ref.get(BODY)
        parent_node = parent_block.get(BODY)
        parent_children = parent_node.get_children()
        # debug('Block:', parent_children)
        for child in parent_children:
            if child == inst:
                # debug('*** Start gathering')
                begin = True
                continue
            if child.kind == ANNOTATION_INST and child.ann_kind == Annotation.ANN_CACHE_END:
                end_conf = json.loads(inst.msg)
                assert end_conf['id'] == conf['id'], 'The begining and end cache id should match'
                # Notify the DFS to skip until the CACHE END
                _set_skip(child)
                # debug('*** Stop gathering')
                break
            if not begin:
                continue
            # debug('   Gather:', child)
            on_miss.append(child)

        # Perform Lookup (Define instructions that are needed for lookup)
        map_name = conf['id'] + '_map'
        index_name = get_tmp_var_name()
        val_ptr = get_tmp_var_name()

        lookup = []
        hash_call = Call(None)
        hash_call.name = '__fnv_hash'
        arg1 = Literal(conf['key'], CODE_LITERAL)
        arg2 = Literal(conf['key_size'], CODE_LITERAL)
        hash_call.args.extend([arg1, arg2])

        decl_index = VarDecl(None)
        decl_index.name = index_name
        decl_index.type = BASE_TYPES[clang.TypeKind.INT]
        decl_index.init.add_inst(hash_call)
        lookup.append(decl_index)

        map_lookup_call = Call(None)
        map_lookup_call.name = 'bpf_map_lookup_elem'
        arg1 = Literal(f'&{map_name}', CODE_LITERAL)
        arg2 = Literal(f'&{index_name}', CODE_LITERAL)
        map_lookup_call.args.extend([arg1, arg2])

        decl_val_ptr = VarDecl(None)
        decl_val_ptr.name = val_ptr
        decl_val_ptr.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
        decl_val_ptr.init.add_inst(map_lookup_call)
        lookup.append(decl_val_ptr)

        val_ref = Ref(None)
        val_ref.name = val_ptr
        val_ref.kind = clang.CursorKind.DECL_REF_EXPR
        val_ref.type = decl_val_ptr.type
        cond = BinOp.build_op(val_ref, '==', Literal('NULL', clang.CursorKind.INTEGER_LITERAL))
        check_miss = ControlFlowInst.build_if_inst(cond)
        # when miss
        check_miss.body.extend_inst(on_miss)
        # when hit
        actual_val = Literal(conf['value_ref'], CODE_LITERAL)
        assign_ref = BinOp.build_op(actual_val, '=', val_ref)
        check_miss.other_body.add_inst(assign_ref)
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
          {conf['value_ref']} = {val_ptr};
        }}
        '''

        # debug(MODULE_TAG, 'instruction for cache miss:', on_miss)

        # Mark the hash function used
        func = Function.directory['__fnv_hash']
        func.is_used_in_bpf_code = True
        info.prog.declarations.insert(0, func)

        blk.extend(lookup)
        # new_inst = Block(BODY)
        # new_inst.extend_inst(lookup)
        # Replace annotation with the block of instruction we have here
        # return new_inst

    # Remove annotation
    return None


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.DECL_REF_EXPR:
        return _check_if_ref_is_global_state(inst, info)
    elif inst.kind == clang.CursorKind.VAR_DECL:
        # TODO: I might want to remove some variable declarations here
        # e.g., ones related to reading/writing responses
        pass
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        if inst.name in READ_PACKET:
            report('Assigning packet buffer to var:', inst.rd_buf.name)
            # Assign packet pointer on a previouse line
            lhs = Literal(inst.rd_buf.name, CODE_LITERAL)
            rhs = info.prog.get_pkt_buf()
            assign_inst = BinOp.build_op(lhs, '=', rhs)
            blk = cb_ref.get(BODY)
            blk.append(assign_inst)
            # TODO: what if `skb` is not defined in this scope?
            # Set the return value
            inst = info.prog.get_pkt_size()
            return inst
        elif inst.name in WRITE_PACKET:
            buf = inst.wr_buf.name
            report(f'Using buffer {buf} to send response')
            # TODO: maybe it is too soon to convert instructions to the code
            if inst.wr_buf.size_cursor is None:
                write_size = Literal('<UNKNOWN WRITE BUF SIZE>', CODE_LITERAL)
            else:
                # write_size, _ = gen_code(inst.wr_buf.size_cursor, info, context=ARG)
                write_size = inst.wr_buf.size_cursor

            if current_function is None:
                # On the main BPF program. feel free to return the verdict value
                inst = info.prog.send(buf, write_size, info)
            else:
                # On a function which is not the main. Do not return
                copy_inst = info.prog.send(buf, write_size, info, ret=False, failure=_get_fail_ret_val())
                # set the flag
                flag_ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
                flag_ref.name = SEND_FLAG_NAME
                flag_ref.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
                deref = UnaryOp(None)
                deref.child.add_inst(flag_ref)
                deref.op = '*'
                one = Literal('1', clang.CursorKind.INTEGER_LITERAL)
                set_flag = BinOp.build_op(deref, '=', one)

                # add it to the body
                blk = cb_ref.get(BODY)
                blk.append(copy_inst)
                blk.append(set_flag)
                # Return from this point to the BPF main
                inst = _get_ret_inst()
            return inst
        elif inst.name in KNOWN_FUNCS:
            # Use known implementations of famous functions
            return _known_function_substitution(inst, info)
        else:
            # TODO: check if the function being invoked needs to receive any flag and pass.
            pass
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
    for func in Function.directory.values():
        if func.is_used_in_bpf_code:
            current_function = func
            _check_func_receives_all_the_flags(func, info)
            func.body = _do_pass(func.body, info, PassObject())
            current_function = None
    return res
