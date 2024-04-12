import json
import clang.cindex as clang
import template
from log import error, debug, report
from utility import get_top_owner
from code_gen import gen_code
from template import SHARED_OBJ_PTR
from prune import READ_PACKET, WRITE_PACKET, KNOWN_FUNCS
from helpers.instruction_helper import (get_ret_inst, add_flag_to_func, ZERO,
        VOID_PTR, get_or_decl_ref, CHAR_PTR)
from helpers.cache_helper import define_internal_cache
from data_structure import *
from my_type import MyType
from instruction import *
from sym_table import MemoryRegion
from elements.after import After
from passes.code_pass import Pass
from passes.update_original_ref import set_original_ref
from passes.clone import clone_pass
from var_names import *
from internal_types import *


MODULE_TAG = '[Transform Vars Pass]'


class TransformVars(Pass):
    def __init__(self, info):
        super().__init__(info)
        self._may_remove = True

    def _is_packet_pointer(self, inst):
        names = self.info.read_decl.get(self.current_fname)
        if names is None:
            return False
        return inst.name in names

    def _process_annotation(self, inst):
        if inst.ann_kind == Annotation.ANN_CACNE_DEFINE:
            decls, conf = define_internal_cache(inst, self.info)
            for d in decls:
                self.info.prog.add_declaration(d)
            map_id = conf['id']
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

    def _process_read_call(self, inst, more):
        blk = self.cb_ref.get(BODY)
        # NOTE: I can assign the pointer but then the buffer size won't be right?
        #           <-- should it be considered as an optimization and applied only
        #           if there is no issues?
        # report('Assigning packet buffer to var:', inst.rd_buf.name)
        # Assign packet pointer on a previouse line

        pkt = self.info.prog.get_pkt_buf()
        data, tmp_decl  = get_or_decl_ref(self.info, DATA_VAR, VOID_PTR,
                init=pkt)
        data.original = inst.original
        self.declare_at_top_of_func.extend(tmp_decl)

        # TODO: __data should be set as bpf_ctx in verifier pass, but since it
        # is a var_decl with initialization, we are not doing it. As a result,
        # I am setting it manually here.
        sym = self.info.sym_tbl.lookup(data.name)
        assert sym is not None
        sym.is_bpf_ctx = True

        lhs = inst.rd_buf.ref
        rhs = data
        rhs.set_modified()
        assign_inst = BinOp.build(lhs, '=', rhs)
        blk.append(assign_inst)
        set_original_ref(assign_inst, self.info, inst.original)
        # Removing read_system call
        assign_inst.set_modified(InstructionColor.REMOVE_READ)
        assign_inst.removed.append(inst)
        # Set the return value
        if more.ctx == BODY:
            # Discard the function return value
            return None
        # Use size of the packet as the return value
        new_inst = self.info.prog.get_pkt_size()
        new_inst.set_modified()
        return new_inst

    def _check_if_ref_is_shared_state(self, inst):
        """
        @return (inst, bool) the new instruction and a flag indicating if it
        was a match or not
        """
        sym, scope = self.info.sym_tbl.lookup2(inst.name)
        is_shared  = scope == self.info.sym_tbl.shared_scope
        if not is_shared:
            return inst, False

        # Get a reference to the shared object. Perform map lookup if needed.
        sym = self.info.sym_tbl.lookup(SHARED_REF_NAME)
        if sym is None:
            # Perform a lookup on the map for globally shared values
            new_insts = template.prepare_shared_state_var(self.current_function)
            blk = self.cb_ref.get(BODY)
            blk.extend(new_insts)
            set_original_ref(new_insts, self.info, inst.original)
            # Update the symbol table
            # TODO: because I am not handling blocks as separate scopes (as
            # they should). I will introduce bugs when shared is defined in an
            # inner scope.
            sym = self.info.sym_tbl.insert_entry(SHARED_REF_NAME,
                    SHARED_OBJ_PTR, None, None)
        shared = Ref.from_sym(sym)

        # Mark the instruction as red, because it will become a lookup from a
        # map
        new_inst = clone_pass(inst)
        new_inst.set_modified()
        # Update the owner
        top_owner = get_top_owner(new_inst)
        top_owner.kind = clang.CursorKind.MEMBER_REF_EXPR
        top_owner.owner.append(shared)
        assert len(top_owner.owner) == 1
        return inst, True

    def _check_if_sock_state(self, inst):
        sym, scope = self.info.sym_tbl.lookup2(inst.name)
        is_sock_state = scope == self.info.sym_tbl.sk_state_scope
        if not is_sock_state:
            return inst, False

        sym = self.info.sym_tbl.lookup(SOCK_STATE_VAR_NAME)
        if sym is None:
            tmp_insts, decl = template.prepare_sock_state_var(self.current_function, self.info)
            self.declare_at_top_of_func.extend(decl)
            blk = self.cb_ref.get(BODY)
            blk.extend(tmp_insts)
            set_original_ref(tmp_insts, self.info, inst.original)
            sym = self.info.sym_tbl.insert_entry(SOCK_STATE_VAR_NAME,
                    SOCK_STATE_PTR, None, None)
        state = Ref.from_sym(sym)
        state = state.get_ref_field('state', self.info)
        # Mark the instruction as red, because it will become a lookup from a
        # map
        new_inst = clone_pass(inst)
        new_inst.set_modified()
        # Update the owner
        top_owner = get_top_owner(new_inst)
        top_owner.kind = clang.CursorKind.MEMBER_REF_EXPR
        top_owner.owner.append(state)
        assert len(top_owner.owner) == 1
        return new_inst, True

    def _process_ref(self, inst, more):
        if self._is_packet_pointer(inst):
            # is packet pointer
            assert inst.type.is_mem_ref(), f'Unexpected type {inst.type}'
            new_inst = clone_pass(inst)
            new_inst.type = CHAR_PTR
            inst = new_inst
            # TODO: maybe I also need to update the type set in the symbol
            # table
        inst, ret = self._check_if_ref_is_shared_state(inst)
        if ret:
            return inst
        inst, ret = self._check_if_sock_state(inst)
        return inst

    def process_current_inst(self, inst, more):
        if inst.kind == clang.CursorKind.DECL_REF_EXPR:
            return self._process_ref(inst, more)
        elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
            assert len(inst.owner) != 0, 'I do not expect a member with out an owner (which probably means an owner from the current class but I am not doing c++)'
            assert len(inst.owner) == 1, 'I expect the instruction to have only one owner (previously more than one was allowed)'
            parent = inst.owner[0]
            tmp = self.process_current_inst(parent, more)
            inst.owner[0] = tmp
            return self._process_ref(inst, more)
        elif inst.kind == clang.CursorKind.VAR_DECL:
            if self._is_packet_pointer(inst):
                # This will become a packet pointer, change the type if needed!
                # TODO: this code does not consider shadowing variables and scopes
                # other than those given to each function.
                # Change the declaration
                new_inst = VarDecl.build(inst.name, CHAR_PTR)
                new_inst.set_modified()
                new_inst.original = inst.original
                # removing allocation of arrays, malloc, ...
                new_inst.removed.append(inst)
                return new_inst
            else:
                # We do not care about this variable
                return inst
        elif inst.kind == clang.CursorKind.CALL_EXPR:
            # debug('func call', inst)
            if inst.name in READ_PACKET:
                # debug('read call:', inst, tag=MODULE_TAG)
                # TODO: if the return value of the function call is ignored, we
                # should remove this instruction.
                return self._process_read_call(inst, more)
            elif inst.name in WRITE_PACKET:
                # NOTE: the write is transformed after verifer pass
                self.skip_children()
                return inst
            elif inst.name in KNOWN_FUNCS:
                return inst
            else:
                # NOTE: previously, here, I was check if the send flag was set
                # inside the callee
                pass
        elif inst.kind == ANNOTATION_INST:
            return self._process_annotation(inst)
        return inst


def transform_vars_pass(inst, info, more):
    """
    Transformations in this pass
    * Global variables
    * Read/Recv instruction
    * cache definition
    """
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
