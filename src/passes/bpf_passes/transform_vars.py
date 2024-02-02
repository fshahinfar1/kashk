import json
import clang.cindex as clang
from log import error, debug, report
from code_gen import gen_code
from template import (prepare_shared_state_var, define_bpf_arr_map,
        SHARED_OBJ_PTR)
from prune import READ_PACKET, WRITE_PACKET, KNOWN_FUNCS
from helpers.instruction_helper import get_ret_inst, add_flag_to_func, ZERO

from data_structure import *
from instruction import *
from sym_table import MemoryRegion
from after import After
from code_pass import Pass


MODULE_TAG = '[Transform Vars Pass]'

SEND_FLAG_NAME = '__send_flag'
FAIL_FLAG_NAME = '__fail_flag'


class TransformVars(Pass):
    def __init__(self, info):
        super().__init__(info)
        self._may_remove = True

    def _process_call_needing_send_flag(self, inst):
        """
        @parm inst, a Call object for a Function which needs a send flag
        @return Instruction
        """
        assert isinstance(inst, Call)
        assert not inst.has_flag(Function.SEND_FLAG)
        blk = self.cb_ref.get(BODY)
        inst.set_flag(Function.SEND_FLAG)
        sym = self.info.sym_tbl.lookup(SEND_FLAG_NAME)
        if self.current_function is None:
            if sym is None:
                # Allocate the flag on the stack and pass a poitner
                CHAR = BASE_TYPES[clang.TypeKind.SCHAR]
                decl = VarDecl.build(SEND_FLAG_NAME, CHAR)
                decl.init.add_inst(ZERO)
                decl.set_modified(InstructionColor.EXTRA_STACK_ALOC)
                self.declare_at_top_of_func.append(decl)
                sym = decl.update_symbol_table(self.info.sym_tbl)
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
        if self.current_function is None:
            # Do we need modify the packet before sending? (e.g., swap IP address)
            before_send_insts = self.info.prog.before_send()
            check.body.extend_inst(before_send_insts)
            # Return the verdict
            ret_val  = self.info.prog.get_send()
            ret_inst = Return.build([ret_val,])
            # It is not marked as 'InstructionColor.REMOVE_WRITE'
            # because the instruction was removed inside the
            # called funcation and we count it there.
            ret_inst.set_modified()
            check.body.add_inst(ret_inst)
        else:
            # Return to the caller func
            assert sym.type.is_pointer()
            ret_inst = get_ret_inst(self.current_function, self.info)
            check.body.add_inst(ret_inst)
        after = After([check,])
        blk.append(after)
        return inst

    def _process_annotation(self, inst):
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
            for d in self.info.prog.declarations:
                if isinstance(d, TypeDefinition) and d.name == val_type:
                    # Found the type
                    break
            else:
                # The value type is not declared yet
                from passes.mark_relevant_code import _add_type_to_declarations
                T = MyType.make_simple(val_type, clang.TypeKind.RECORD)
                _add_type_to_declarations(T, self.info)

            self.info.prog.add_declaration(m)
            assert map_id not in self.info.map_definitions, 'Multiple deffinition of the same map id'
            self.info.map_definitions[map_id] = conf
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

    def _process_read_call(self, inst):
        blk = self.cb_ref.get(BODY)
        # NOTE: I can assign the pointer but then the buffer size won't be right?
        #           <-- should it be considered as an optimization and applied only
        #           if there is no issues?
        # report('Assigning packet buffer to var:', inst.rd_buf.name)
        # Assign packet pointer on a previouse line
        lhs = inst.rd_buf.ref
        rhs = self.info.prog.get_pkt_buf()
        rhs.set_modified()
        assign_inst = BinOp.build(lhs, '=', rhs)
        blk.append(assign_inst)
        # Removing read_system call
        assign_inst.set_modified(InstructionColor.REMOVE_READ)
        assign_inst.removed.append(inst)
        # Set the return value
        new_inst = self.info.prog.get_pkt_size()
        new_inst.set_modified()
        return new_inst

    def _check_if_ref_is_global_state(self, inst):
        sym, scope = self.info.sym_tbl.lookup2(inst.name)
        is_shared = scope == self.info.sym_tbl.shared_scope
        if not is_shared:
            return inst
        # Mark the instruction as red, because it will become a lookup from a
        # map
        # TODO: maybe it is better that I change the owner
        inst.set_modified()
        sym = self.info.sym_tbl.lookup('shared')
        if sym is not None:
            return inst
        # debug('load shared map for variable:', inst.name)
        # Perform a lookup on the map for globally shared values
        ret_inst = get_ret_inst(self.current_function, self.info)
        new_insts = prepare_shared_state_var(ret_val=ret_inst)
        blk = self.cb_ref.get(BODY)
        blk.extend(new_insts)
        # Update the symbol table
        # TODO: because I am not handling blocks as separate scopes (as
        # they should). I will introduce bugs when shared is defined in an
        # inner scope.
        entry = self.info.sym_tbl.insert_entry('shared', SHARED_OBJ_PTR,
                None, None)
        entry.set_mem_region(MemoryRegion.STACK)
        entry.set_ref_region(MemoryRegion.BPF_MAP)
        return inst

    def process_current_inst(self, inst, more):
        if inst.kind == clang.CursorKind.DECL_REF_EXPR:
            return self._check_if_ref_is_global_state(inst)
        elif inst.kind == clang.CursorKind.VAR_DECL:
            if self.current_function is None:
                cur_func_name = '[[main]]'
            else:
                cur_func_name = self.current_function.name
            names = self.info.read_decl.get(cur_func_name, set())
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
            debug('func call', inst)
            if inst.name in READ_PACKET:
                debug('read call:', inst, tag=MODULE_TAG)
                # TODO: if the return value of the function call is ignored, we
                # should remove this instruction.
                return self._process_read_call(inst)
            elif inst.name in WRITE_PACKET:
                # NOTE: the writel or libc calls are transformed after verifer pass
                self.skip_children()
                return inst
            elif inst.name in KNOWN_FUNCS:
                return inst
            else:
                # Check if the function being invoked needs to
                # receive any flag and pass.
                func = inst.get_function_def()
                if not func:
                    return inst
                tmp = func.calls_recv or func.calls_send
                req_ctx = tmp and not inst.has_flag(Function.CTX_FLAG)
                if req_ctx:
                    # Add context
                    assert func.change_applied & Function.CTX_FLAG != 0, 'The function call is determined to requier context pointer but the function signiture is not updated'
                    inst.change_applied |= Function.CTX_FLAG
                    inst.args.append(self.info.prog.get_ctx_ref())
                    inst.set_modified(InstructionColor.ADD_ARGUMENT)
                    # debug('add ctx ref to call:', inst.name)

                # Add send flag
                if func.calls_send and not inst.has_flag(Function.SEND_FLAG):
                    new_inst = self._process_call_needing_send_flag(inst)
                    return new_inst

                # NOTE: fail flag is added in userspace_fallback (future pass)
        elif inst.kind == ANNOTATION_INST:
            return self._process_annotation(inst)
        return inst


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
    # First check function definitions and flags they receive
    for func in Function.directory.values():
        if not func.is_used_in_bpf_code:
            continue
        with info.sym_tbl.with_func_scope(func.name):
            _check_func_receives_all_the_flags(func, info)
    # Process the main
    tmp = TransformVars.do(inst, info, more)
    res = tmp.result
    # Process other functions
    for func in Function.directory.values():
        if not func.is_used_in_bpf_code:
            continue
        tmp = TransformVars.do(func.body, info, func=func)
        func.body = tmp.result
        current_function = None
    return res
