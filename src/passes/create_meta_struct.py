import clang.cindex as clang
from log import debug
from instruction import *
from data_structure import *
from passes.code_pass import Pass
from passes.clone import clone_pass

from helpers.instruction_helper import UINT
from var_names import FAILURE_NUMBER_FIELD, UNIT_SIZE


def create_fallback_meta_structure(info):
    book = {}
    similar_paths = {}
    for path_id, V in info.failure_vars.items():
        state_obj = StateObject.build(FAILURE_NUMBER_FIELD, UINT)
        fields = [state_obj,]
        for sym in V:
            T = sym.type.clone()
            f = StateObject.build(sym.name, T)
            fields.append(f)
            
        meta = Record(f'meta_{path_id}', fields)
        book[path_id] = meta
        assert meta.type.mem_size < UNIT_SIZE, 'we want to share more data that we can put on a channel unit'

    path_ids = tuple(book.keys())
    for p in path_ids:
        similar_paths[p] = set()

    # Check if we can merge the data-structs
    for i, path_id1 in enumerate(path_ids):
        meta1 = book[path_id1]
        if len(similar_paths[path_id1]) > 0:
            continue
        for path_id2 in path_ids[i+1:]:
            meta2 = book[path_id2]
            if len(meta1.fields) != len(meta2.fields):
                # Not same data-structure
                continue
            same = all(map(lambda x: x[0]==x[1],
                            zip(meta1.fields, meta2.fields)))
            if not same:
                print(path_id1,'not similar to', path_id2, 'because:', x)
                continue
            book[path_id2] = meta1
            # similar_paths[path_id1].add(path_id2)
            similar_paths[path_id2].add(path_id1)

    # Add meta structs to the code
    for path_id, meta in book.items():
        info.user_prog.declarations[path_id] = meta
        if len(similar_paths[path_id]) > 0:
            # we have already defined this data-structure
            continue
        meta.is_used_in_bpf_code = True
        info.prog.add_declaration(meta)
        gs = info.sym_tbl.global_scope
        with info.sym_tbl.with_scope(gs):
            meta.update_symbol_table(info.sym_tbl)
