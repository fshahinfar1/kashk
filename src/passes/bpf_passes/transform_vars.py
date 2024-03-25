import json
import clang.cindex as clang
from log import error, debug, report
from code_gen import gen_code
from template import (prepare_shared_state_var, define_bpf_arr_map,
        SHARED_OBJ_PTR)
from prune import READ_PACKET, WRITE_PACKET, KNOWN_FUNCS
from helpers.instruction_helper import (get_ret_inst, add_flag_to_func, ZERO,
        VOID_PTR, get_or_decl_ref)
from data_structure import *
from my_type import MyType
from instruction import *
from sym_table import MemoryRegion
from elements.after import After
from passes.code_pass import Pass
from passes.update_original_ref import set_original_ref
from var_names import SHARED_REF_NAME, SEND_FLAG_NAME, DATA_VAR


MODULE_TAG = '[Transform Vars Pass]'


class TransformVars(Pass):
    def __init__(self, info):
        super().__init__(info)
        self._may_remove = True

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
        self.declare_at_top_of_func.extend(tmp_decl)

        # TODO:
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

    def _check_if_ref_is_global_state(self, inst):
        sym, scope = self.info.sym_tbl.lookup2(inst.name)
        is_shared = scope == self.info.sym_tbl.shared_scope
        if not is_shared:
            return inst
        # Mark the instruction as red, because it will become a lookup from a
        # map
        # TODO: maybe it is better that I change the owner
        inst.set_modified()
        sym = self.info.sym_tbl.lookup(SHARED_REF_NAME)
        if sym is not None:
            return inst
        # debug('load shared map for variable:', inst.name)
        # Perform a lookup on the map for globally shared values
        new_insts = prepare_shared_state_var(self.current_function)
        blk = self.cb_ref.get(BODY)
        blk.extend(new_insts)
        set_original_ref(new_insts, self.info, inst.original)
        # Update the symbol table
        # TODO: because I am not handling blocks as separate scopes (as
        # they should). I will introduce bugs when shared is defined in an
        # inner scope.
        entry = self.info.sym_tbl.insert_entry(SHARED_REF_NAME, SHARED_OBJ_PTR,
                None, None)
        return inst

    def process_current_inst(self, inst, more):
        if inst.kind == clang.CursorKind.DECL_REF_EXPR:
            return self._check_if_ref_is_global_state(inst)
        elif inst.kind == clang.CursorKind.VAR_DECL:
            names = self.info.read_decl.get(self.current_fname, set())
            if inst.name in names:
                # This will become a packet pointer, change the type if needed!
                # TODO: this code does not consider shadowing variables and scopes
                # other than those given to each function.
                # Change the declaration
                T = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
                new_inst = VarDecl.build(inst.name, T)
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
