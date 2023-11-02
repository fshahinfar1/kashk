import json
import clang.cindex as clang
from log import error, debug, report
from bpf_code_gen import gen_code
from template import (prepare_shared_state_var, define_bpf_arr_map,
        define_bpf_hash_map, malloc_lookup)
from prune import READ_PACKET, WRITE_PACKET, KNOWN_FUNCS
from utility import get_tmp_var_name, show_insts
from helpers.cache_helper import generate_cache_lookup
from helpers.instruction_helper import get_ret_inst

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
declare_at_top_of_func = []
ZERO = Literal('0', clang.CursorKind.INTEGER_LITERAL)


class After:
    def __init__(self, box):
        self.box = box


def _set_skip(val):
    global skip_to_end
    skip_to_end = val


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
        assert map_id not in info.map_definitions, 'Multiple deffinition of the same map id'
        info.map_definitions[map_id] = conf
        # report('Declare map', m, 'for malloc')
    elif inst.ann_kind == Annotation.ANN_CACHE_END:
        # Nothing to do
        pass
    elif inst.ann_kind == Annotation.ANN_CACHE_BEGIN:
        blk = cb_ref.get(BODY)
        parent_node = parent_block.get(BODY)
        parent_children = parent_node.get_children()
        new_inst, to_be_declared, skip_target = generate_cache_lookup(inst, blk, parent_children, info)
        declare_at_top_of_func.extend(to_be_declared)
        _set_skip(skip_target)
        return new_inst
    elif inst.ann_kind == Annotation.ANN_CACHE_BEGIN_UPDATE:
        # Moved to 2nd Transformation
        return inst
    elif inst.ann_kind == Annotation.ANN_CACHE_END_UPDATE:
        # TODO: do I want to have some code after update ??
        pass
    # Remove annotation
    return None


def _process_read_call(inst, info):
    blk = cb_ref.get(BODY)

    # NOTE: I can assign the pointer but then the buffer size won't be right? <-- should be looked at as an optimization?
    # report('Assigning packet buffer to var:', inst.rd_buf.name)
    # Assign packet pointer on a previouse line
    lhs = inst.rd_buf.ref
    rhs = info.prog.get_pkt_buf()
    assign_inst = BinOp.build(lhs, '=', rhs)
    blk.append(assign_inst)
    # TODO: what if `skb` is not defined in this scope?
    # Set the return value
    inst = info.prog.get_pkt_size()

    # sz_decl = VarDecl.build(get_tmp_var_name(), BASE_TYPES[clang.TypeKind.USHORT])
    # declare_at_top_of_func.append(sz_decl)
    # sz_ref  = sz_decl.get_ref()
    # sz_assign  = BinOp.build(sz_ref, '=', info.prog.get_pkt_size())
    # blk.append(sz_assign)
    # sz_mask = BinOp.build(sz_ref, '&', Literal('PKT_OFFSET_MASK', clang.CursorKind.MACRO_INSTANTIATION))
    # sz_assign_mask = BinOp.build(sz_ref, '=', sz_mask)
    # blk.append(sz_assign_mask)

    # # check size is less than map buffer size
    # size_check_cond = BinOp.build(sz_ref, '>', Literal('1000', clang.CursorKind.INTEGER_LITERAL))
    # size_check = ControlFlowInst.build_if_inst(size_check_cond)
    # size_check.body.add_inst(_get_ret_inst())
    # blk.append(size_check)


    # # Copy data from XDP to Buffer
    # lhs = Literal(inst.rd_buf.name, CODE_LITERAL)
    # rhs = info.prog.get_pkt_buf()
    # # TODO: check if context is used
    # # dst_end = Literal('<not set>', CODE_LITERAL)
    # # TODO: cast lhs to void *
    # dst_end = BinOp.build(lhs, '+', Literal(inst.rd_buf.size_cursor, CODE_LITERAL))
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


def _process_call_needing_send_flag(inst, blk, current_function, info):
    """
    @parm inst, a Call object for a Function which needs a send flag
    @parm blk
    @parm current_function
    @parm info
    @return Instruction
    """
    inst.change_applied |= Function.SEND_FLAG
    sym = info.sym_tbl.lookup(SEND_FLAG_NAME)
    if current_function is None:
        assert sym is None
        # Allocate the flag on the stack and pass a poitner
        decl = VarDecl(None)
        decl.name = SEND_FLAG_NAME
        decl.type = BASE_TYPES[clang.TypeKind.SCHAR]
        decl.init.add_inst(Literal('0', clang.CursorKind.INTEGER_LITERAL))
        declare_at_top_of_func.append(decl)
        sym = info.sym_tbl.insert_entry(decl.name, decl.type, decl.kind, None)

        flag_ref = decl.get_ref()
        ref = UnaryOp.build('&', flag_ref)
        inst.args.append(ref)
    else:
        # Just pass the reference
        assert sym is not None and sym.type.is_pointer()
        flag_ref = Ref.from_sym(sym)
        inst.args.append(flag_ref)
    # Check the flag after the function
    if flag_ref.type.is_pointer():
        flag_val = UnaryOp.build('*', flag_ref)
    else:
        flag_val = flag_ref
    cond  = BinOp.build(flag_val, '!=', ZERO)
    check = ControlFlowInst.build_if_inst(cond)
    if current_function is None:
        ret_val  = Literal(info.prog.get_send(), clang.CursorKind.INTEGER_LITERAL)
        ret_inst = Instruction()
        ret_inst.kind = clang.CursorKind.RETURN_STMT
        ret_inst.body = [ret_val,]
        check.body.add_inst(ret_inst)
    else:
        assert sym.type.is_pointer()
        ret_inst = get_ret_inst(current_function, info)
        check.body.add_inst(ret_inst)
    after = After([check,])
    blk.append(after)
    return inst


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.DECL_REF_EXPR:
        return _check_if_ref_is_global_state(inst, info)
    elif inst.kind == clang.CursorKind.VAR_DECL:
        # TODO: I might want to remove some variable declarations here
        # e.g., ones related to reading/writing responses
        return inst
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        if inst.name in READ_PACKET:
            return _process_read_call(inst, info)
        elif inst.name in WRITE_PACKET:
            # NOTE: the write calls are transformed after verifer pass
            return inst
        elif inst.name in KNOWN_FUNCS:
            # NOTE: the known function calls are transformed after verifer pass
            return inst
        else:
            # Check if the function being invoked needs to receive any flag and pass.
            func = inst.get_function_def()
            if not func:
                return inst
            # Add context
            if (func.calls_recv  or func.calls_send) and (inst.change_applied & Function.CTX_FLAG == 0):
                inst.change_applied |= Function.CTX_FLAG
                ctx_ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
                ctx_ref.name = info.prog.ctx
                ctx_ref.type = info.prog.ctx_type
                inst.args.append(ctx_ref)

            # Add send flag
            if func.calls_send and (inst.change_applied & Function.SEND_FLAG == 0):
                blk = cb_ref.get(BODY)
                inst = _process_call_needing_send_flag(inst, blk, current_function, info)

            # NOTE: fail flag is added in userspace_fallback
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

                    after = []
                    while new_child and isinstance(new_child[-1], After):
                        after.append(new_child.pop())
                    new_child.append(new_inst)
                    for a in reversed(after):
                        new_child.extend(a.box)
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
        info.prog.add_args_to_scope(info.sym_tbl.current_scope)

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
