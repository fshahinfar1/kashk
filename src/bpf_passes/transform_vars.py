import clang.cindex as clang
from log import error, debug
from bpf_code_gen import gen_code
from template import (prepare_shared_state_var, bpf_get_data,
        send_response_template)
from prune import READ_PACKET, WRITE_PACKET

from data_structure import *
from instruction import *
from passes.pass_obj import PassObject


MODULE_TAG = '[Transform Vars Pass]'
cb_ref = CodeBlockRef()


def _check_if_ref_is_global_state(inst, info):
    sym, scope = info.sym_tbl.lookup2(inst.name)
    is_shared = scope == info.sym_tbl.shared_scope
    if is_shared:
        # Keep track of used global variables
        info.global_accessed_variables.add(inst.name)
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


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.DECL_REF_EXPR:
        return _check_if_ref_is_global_state(inst, info)
    elif inst.kind == clang.CursorKind.VAR_DECL:
        # Handle read buffer transformation
        if inst.name == info.rd_buf.name:
            # The previouse passes should have seperated the initialization
            # from declaration
            assert inst.has_children() is False
            new_inst = VarDecl(None)
            new_inst.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
            new_inst.name = inst.name
            e = info.sym_tbl.insert_entry(inst.name, new_inst.type, new_inst.kind, None)
            e.is_bpf_ctx = True
            # replace this instruction
            return new_inst
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        if inst.name in READ_PACKET:
            # Assign packet pointer on a previouse line
            text = bpf_get_data(info.rd_buf.name)
            assign_inst = Literal(text, CODE_LITERAL)
            blk = cb_ref.get(BODY)
            blk.append(assign_inst)
            # TODO: what if `skb` is not defined in this scope?
            # Set the return value
            text = f'skb->len'
            inst = Literal(text, CODE_LITERAL)
            return inst
        elif inst.name in WRITE_PACKET:
            buf = info.wr_buf.name
            # TODO: maybe it is too soon to convert instructions to the code
            write_size, _ = gen_code(info.wr_buf.write_size_cursor, info, context=ARG)
            text = send_response_template(buf, write_size)
            inst = Literal(text, CODE_LITERAL)
            return inst

    return inst


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
    new_children = []

    if inst.bpf_ignore is True:
        return None

    with cb_ref.new_ref(ctx, parent_list):
        # Process current instruction
        inst = _process_current_inst(inst, info, more)
        if inst is None:
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
                new_child.append(new_inst)
            if not is_list:
                if len(new_child) < 1:
                    return None
                assert len(new_child) == 1, f'expect to receive one object (count = {len(new_child)})'
                new_child = new_child[-1]
            new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def transform_vars_pass(inst, info, more):
    return _do_pass(inst, info, more)
