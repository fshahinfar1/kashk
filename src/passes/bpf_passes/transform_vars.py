import json
import clang.cindex as clang
from log import error, debug, report
from code_gen import gen_code
from template import (prepare_shared_state_var, define_bpf_arr_map,
        SHARED_OBJ_PTR)
from prune import READ_PACKET, WRITE_PACKET, KNOWN_FUNCS
from utility import get_tmp_var_name
from helpers.instruction_helper import get_ret_inst, add_flag_to_func, ZERO

from data_structure import *
from instruction import *
from sym_table import MemoryRegion
from passes.pass_obj import PassObject
from after import After


MODULE_TAG = '[Transform Vars Pass]'

SEND_FLAG_NAME = '__send_flag'
FAIL_FLAG_NAME = '__fail_flag'

cb_ref = CodeBlockRef()
current_function = None
declare_at_top_of_func = []



def _check_if_ref_is_global_state(inst, info):
    sym, scope = info.sym_tbl.lookup2(inst.name)
    is_shared = scope == info.sym_tbl.shared_scope
    if is_shared:
        sym = info.sym_tbl.lookup('shared')
        if sym is None:
            # Perform a lookup on the map for globally shared values
            ret_inst = get_ret_inst(current_function, info)
            new_insts = prepare_shared_state_var(ret_val=ret_inst)
            code = cb_ref.get(BODY)
            code.extend(new_insts)
            # Update the symbol table
            # TODO: because I am not handling blocks as separate scopes (as
            # they should). I will introduce bugs when shared is defined in an
            # inner scope.
            entry = info.sym_tbl.insert_entry('shared', SHARED_OBJ_PTR,
                    None, None)
            entry.set_mem_region(MemoryRegion.STACK)
            entry.set_ref_region(MemoryRegion.BPF_MAP)
        # Mark the instruction as red, because it will become a lookup from a
        # map
        inst.set_modified()
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
            from passes.mark_relevant_code import _add_type_to_declarations
            T = MyType.make_simple(val_type, clang.TypeKind.RECORD)
            _add_type_to_declarations(T, info)

        info.prog.add_declaration(m)
        assert map_id not in info.map_definitions, 'Multiple deffinition of the same map id'
        info.map_definitions[map_id] = conf
        # report('Declare map', m, 'for malloc')
    elif inst.ann_kind == Annotation.ANN_CACHE_BEGIN:
        # Moved to 2nd Transformation
        return inst
    elif inst.ann_kind == Annotation.ANN_CACHE_END:
        # Moved to 2nd Transformation
        return inst
    elif inst.ann_kind == Annotation.ANN_CACHE_BEGIN_UPDATE:
        # Moved to 2nd Transformation
        return inst
    elif inst.ann_kind == Annotation.ANN_CACHE_END_UPDATE:
        # Moved to 2nd Transformation
        return inst
    # Remove annotation
    return None


def _process_read_call(inst, info):
    blk = cb_ref.get(BODY)

    # NOTE: I can assign the pointer but then the buffer size won't be right?
    #           <-- should it be considered as an optimization and applied only
    #           if there is no issues?

    # report('Assigning packet buffer to var:', inst.rd_buf.name)
    # Assign packet pointer on a previouse line
    lhs = inst.rd_buf.ref
    rhs = info.prog.get_pkt_buf()
    rhs.set_modified()
    assign_inst = BinOp.build(lhs, '=', rhs)
    blk.append(assign_inst)
    # Removing read_system call
    assign_inst.set_modified(InstructionColor.REMOVE_READ)
    assign_inst.removed.append(inst)
    # Set the return value
    new_inst = info.prog.get_pkt_size()
    new_inst.set_modified()
    return new_inst


def _process_call_needing_send_flag(inst, blk, current_function, info):
    """
    @parm inst, a Call object for a Function which needs a send flag
    @parm blk
    @parm current_function
    @parm info
    @return Instruction
    """
    inst.set_flag(Function.SEND_FLAG)
    sym = info.sym_tbl.lookup(SEND_FLAG_NAME)
    if current_function is None:
        if sym is None:
            # Allocate the flag on the stack and pass a poitner
            CHAR = BASE_TYPES[clang.TypeKind.SCHAR]
            decl = VarDecl.build(SEND_FLAG_NAME, CHAR)
            decl.init.add_inst(ZERO)
            decl.set_modified(InstructionColor.EXTRA_STACK_ALOC)
            declare_at_top_of_func.append(decl)
            sym = decl.update_symbol_table(info.sym_tbl)
            flag_ref = decl.get_ref()
        else:
            flag_ref = Ref.from_sym(sym)
            assert not flag_ref.type.is_pointer()
        ref = UnaryOp.build('&', flag_ref)
        inst.args.append(ref)
        inst.set_modified(InstructionColor.ADD_ARGUMENT)
    else:
        # Just pass the reference, the function must have received a flag from
        # the entry scope
        assert sym is not None and sym.type.is_pointer()
        flag_ref = Ref.from_sym(sym)
        inst.args.append(flag_ref)
        inst.set_modified(InstructionColor.ADD_ARGUMENT)
    # Check the flag after the function
    if flag_ref.type.is_pointer():
        flag_val = UnaryOp.build('*', flag_ref)
    else:
        flag_val = flag_ref
    cond  = BinOp.build(flag_val, '!=', ZERO)
    cond.set_modified()
    check = ControlFlowInst.build_if_inst(cond)
    check.set_modified(InstructionColor.CHECK)
    if current_function is None:
        # Do we need modify the packet before sending? (e.g., swap IP address)
        before_send_insts = info.prog.before_send()
        check.body.extend_inst(before_send_insts)
        # Return the verdict
        ret_val  = Literal(info.prog.get_send(), clang.CursorKind.INTEGER_LITERAL)
        ret_inst = Return.build([ret_val,])
        check.body.add_inst(ret_inst)
    else:
        # Return to the caller func
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
        current_func_name = \
                current_function.name if current_function else '[[main]]'
        names = info.read_decl.get(current_func_name, set())
        if inst.name in names:
            # This will become a packet pointer, change the type if needed!
            # TODO: this code does not consider shadowing variables and scopes
            # other than those given to each function.
            if (inst.type.is_pointer() and
                    inst.type.get_pointee().kind == clang.TypeKind.SCHAR):
                # The type is okay
                return inst
            # Change the declaration
            T = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
            new_inst = VarDecl.build(inst.name, T)
            new_inst.set_modified()
            # removing allocation of arrays, malloc, ...
            new_inst.removed.append(inst)
            return new_inst
        else:
            # We do not care about this variable
            return inst
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        if inst.name in READ_PACKET:
            # TODO: if the return value of the function call is ignored, we
            # should remove this instruction.
            return _process_read_call(inst, info)
        elif inst.name in (WRITE_PACKET + KNOWN_FUNCS):
            # NOTE: the writel or libc calls are transformed after verifer pass
            return inst
        else:
            # Check if the function being invoked needs to receive any flag and
            # pass.
            func = inst.get_function_def()
            if not func:
                return inst
            tmp = func.calls_recv or func.calls_send
            req_ctx = tmp and not inst.has_flag(Function.CTX_FLAG)
            if req_ctx:
                # Add context
                assert func.change_applied & Function.CTX_FLAG != 0, 'The function call is determined to requier context pointer but the function signiture is not updated'
                inst.change_applied |= Function.CTX_FLAG
                inst.args.append(info.prog.get_ctx_ref())
                inst.set_modified(InstructionColor.ADD_ARGUMENT)
                # debug('add ctx ref to call:', inst.name)

            # Add send flag
            if func.calls_send and not inst.has_flag(Function.SEND_FLAG):
                blk = cb_ref.get(BODY)
                inst = _process_call_needing_send_flag(inst, blk, current_function, info)

            # NOTE: fail flag is added in userspace_fallback (future pass)
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
        for child, tag in inst.get_children_context_marked():
            is_list = isinstance(child, list)
            if not is_list:
                child = [child]
            new_child = []
            for i in child:
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
    # debug("check func", func.name, 'send or recv?', func.calls_send, func.calls_recv)
    if (func.calls_send or func.calls_recv) and (func.change_applied & Function.CTX_FLAG == 0):
        # Add the BPF context to its arguemt
        add_flag_to_func(Function.CTX_FLAG, func, info)
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

    * Pass flags to the functions
    * Global variables
    * Read/Recv instruction
    * Write/Send instructions
    * Known function substitution
    * Cache Generation
    """
    global current_function


    # First check function definitions and flags they receive
    for func in Function.directory.values():
        if not func.is_used_in_bpf_code:
            continue
        current_function = func
        with info.sym_tbl.with_func_scope(current_function.name):
            _check_func_receives_all_the_flags(func, info)


    # Process the main
    current_function = None
    res = _do_pass(inst, info, more)
    if declare_at_top_of_func:
        for inst in declare_at_top_of_func:
            res.children.insert(0, inst)
    declare_at_top_of_func.clear()

    # Process other functions
    for func in Function.directory.values():
        if not func.is_used_in_bpf_code:
            continue
        current_function = func
        with info.sym_tbl.with_func_scope(current_function.name):
            func.body = _do_pass(func.body, info, PassObject())
            if declare_at_top_of_func:
                for inst in declare_at_top_of_func:
                    func.body.children.insert(0, inst)
            declare_at_top_of_func.clear()
        current_function = None
    return res
