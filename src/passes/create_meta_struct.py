import clang.cindex as clang
from log import debug
from instruction import *
from data_structure import *
from passes.code_pass import Pass
from passes.clone import clone_pass

from helpers.instruction_helper import INT
from var_names import FAILURE_NUMBER_FIELD, UNIT_SIZE




def create_fallback_meta_structure(info):
    for path_id, V in info.failure_vars.items():
        state_obj = StateObject.build(FAILURE_NUMBER_FIELD, INT)
        fields = [state_obj,]
        for sym in V:
            T = sym.type.clone()
            f = StateObject.build(sym.name, T)
            fields.append(f)
            
        meta = Record(f'meta_{path_id}', fields)
        meta.is_used_in_bpf_code = True
        info.prog.add_declaration(meta)
        info.user_prog.declarations[path_id] = meta

        gs = info.sym_tbl.global_scope
        with info.sym_tbl.with_scope(gs):
            meta.update_symbol_table(info.sym_tbl)

        assert meta.type.mem_size < UNIT_SIZE, 'we want to share more data that we can put on a channel unit'
