import clang.cindex as clang
from log import error, debug, report
from bpf_code_gen import gen_code
from template import prepare_shared_state_var, bpf_get_data, send_response_template, define_bpf_arr_map, malloc_lookup
from prune import READ_PACKET, WRITE_PACKET, KNOWN_FUNCS

from data_structure import *
from instruction import *
from passes.pass_obj import PassObject


MODULE_TAG = '[Transform Vars Pass]'
cb_ref = CodeBlockRef()

_malloc_map_counter = 0
def _get_malloc_name():
    global _malloc_map_counter
    _malloc_map_counter += 1
    return f'malloc_{_malloc_map_counter}'

def _known_function_substitution(inst, info):
    if inst.name == 'strlen':
        inst.name = 'bpf_strlen'
        # Mark the function used
        func = inst.get_function_def()
        assert func is not None
        func.is_used_in_bpf_code = True
        info.prog.declarations.append(func)
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
        lookup_inst = malloc_lookup(name)

        return lookup_inst
        # Add the instructions
        # blk = cb_ref.get(BODY)
        # code.append(lookup_inst)
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
            text = bpf_get_data(inst.rd_buf.name)
            assign_inst = Literal(text, CODE_LITERAL)
            blk = cb_ref.get(BODY)
            blk.append(assign_inst)
            # TODO: what if `skb` is not defined in this scope?
            # Set the return value
            text = f'skb->len'
            inst = Literal(text, CODE_LITERAL)
            return inst
        elif inst.name in WRITE_PACKET:
            buf = inst.wr_buf.name
            report(f'Using buffer {buf} to send response')
            # TODO: maybe it is too soon to convert instructions to the code
            if inst.wr_buf.size_cursor is None:
                write_size = '<UNKNOWN WRITE BUF SIZE>'
            else:
                write_size, _ = gen_code(inst.wr_buf.size_cursor, info, context=ARG)
            text = send_response_template(buf, write_size)
            inst = Literal(text, CODE_LITERAL)
            return inst
        elif inst.name in KNOWN_FUNCS:
            # Use known implementations of famous functions
            return _known_function_substitution(inst, info)
    return inst


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
    new_children = []

    with cb_ref.new_ref(ctx, parent_list):
        # Process current instruction
        inst = _process_current_inst(inst, info, more)
        if inst is None:
            debug(MODULE_TAG, 'remove instruction:', inst)
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
                    debug(MODULE_TAG, 'remove instruction:', inst)
                    return None
                assert len(new_child) == 1, f'expect to receive one object (count = {len(new_child)})'
                new_child = new_child[-1]
            new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def transform_vars_pass(inst, info, more):
    res = _do_pass(inst, info, more)
    for func in Function.directory.values():
        if func.is_used_in_bpf_code:
            _do_pass(func.body, info, PassObject())
    return res
