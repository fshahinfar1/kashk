import clang.cindex as clang
from contextlib import contextmanager

from log import error, debug, report
from data_structure import *
from instruction import *
from prune import WRITE_PACKET, KNOWN_FUNCS
from template import define_bpf_arr_map, malloc_lookup
from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from bpf_passes.transform_vars import SEND_FLAG_NAME
from helpers.bpf_ctx_helper import is_bpf_ctx_ptr, is_value_from_bpf_ctx
from helpers.instruction_helper import get_ret_inst
from helpers.cache_helper import generate_cache_update


MODULE_TAG = '[2nd Transform]'
cb_ref = CodeBlockRef()
current_function = None
_has_processed_func = set()
declare_at_top_of_func = None


@contextmanager
def set_current_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield func
    finally:
        current_function = tmp


_malloc_map_counter = 0
def _get_malloc_name():
    global _malloc_map_counter
    _malloc_map_counter += 1
    return f'malloc_{_malloc_map_counter}'


def _rename_func_to_a_known_one(inst, info, target_name):
    inst.name = target_name
    # Mark the function used
    func = inst.get_function_def()
    assert func is not None
    if not func.is_used_in_bpf_code:
        func.is_used_in_bpf_code = True
        info.prog.declarations.insert(0, func)
    # debug(MODULE_TAG, 'Add func:', func.name)
    return inst


def _known_function_substitution(inst, info):
    """
    Replace some famous functions with implementations that work in BPF
    """
    if inst.name == 'strlen':
        return _rename_func_to_a_known_one(inst, info, 'bpf_strlen')
    elif inst.name == 'strncpy':
        assert len(inst.args) == 3, 'Assumption on the number of arguments'
        buf = inst.args[0]
        if is_bpf_ctx_ptr(buf, info):
            end_dest = info.prog.get_pkt_end()
        else:
            end_dest = BinOp.build_op(buf, '+', inst.args[2])
        # end_src = BinOp.build_op(inst.args[1], '+', inst.args[2])
        inst.args.extend([end_dest,])
        return _rename_func_to_a_known_one(inst, info, 'bpf_strncpy')
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

        __scope = info.sym_tbl.current_scope
        info.sym_tbl.current_scope = info.sym_tbl.global_scope
        value_type.update_symbol_table(info.sym_tbl)
        info.sym_tbl.current_scope = __scope
        report('Declare', value_type, 'as malloc object')

        # Define the map
        m = define_bpf_arr_map(map_name, f'struct {name}', 1)
        info.prog.add_declaration(m)
        report('Declare map', m, 'for malloc')

        # Look the malloc map
        return_val = get_ret_inst(current_function, info).body[0].text
        lookup_inst, ref = malloc_lookup(name, info, return_val)
        blk = cb_ref.get(BODY)
        for tmp_inst in lookup_inst:
            blk.append(tmp_inst)
        return ref
    elif inst.name in ('ntohs', 'ntohl', 'htons', 'htonl'):
        inst.name = 'bpf_'+inst.name
        return inst
    elif inst.name == 'htonll':
        inst.name = 'bpf_cpu_to_be64'
        return inst
    elif inst.name == 'ntohll':
        inst.name = 'bpf_be64_to_cpu'
        return inst
    error(f'Know function {inst.name} is not implemented yet')
    return inst


def _process_write_call(inst, info):
    buf = inst.wr_buf.name
    report(f'Using buffer {buf} to send response')
    # TODO: maybe it is too soon to convert instructions to the code
    if inst.wr_buf.size_cursor is None:
        write_size = Literal('<UNKNOWN WRITE BUF SIZE>', CODE_LITERAL)
    else:
        # write_size, _ = gen_code(inst.wr_buf.size_cursor, info, context=ARG)
        write_size = inst.wr_buf.size_cursor


    ref = inst.wr_buf.ref
    should_copy = not is_bpf_ctx_ptr(ref, info)

    if current_function is None:
        # On the main BPF program. feel free to return the verdict value
        inst = info.prog.send(buf, write_size, info, do_copy=should_copy)
    else:
        # On a function which is not the main. Do not return
        return_val = get_ret_inst(current_function, info).body[0].text
        copy_inst = info.prog.send(buf, write_size, info, ret=False, failure=return_val, do_copy=should_copy)
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
        inst = get_ret_inst(current_function, info)
    return inst


def _process_call_inst(inst, info):
    if inst.name in WRITE_PACKET:
        return _process_write_call(inst, info)
    elif inst.name in KNOWN_FUNCS:
        return _known_function_substitution(inst, info)
    return inst


def _process_annotation(inst, info):
    if inst.ann_kind == Annotation.ANN_CACHE_BEGIN_UPDATE:
        blk = cb_ref.get(BODY)
        new_inst, to_be_declared = generate_cache_update(inst, blk, current_function, info)
        declare_at_top_of_func.extend(to_be_declared)
        return new_inst


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        return _process_call_inst(inst,info)
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
            return None
        # Continue deeper
        for child, tag in inst.get_children_context_marked():
            if isinstance(child, list):
                new_child = []
                for i in child:
                    obj = PassObject.pack(lvl+1, tag, new_child)
                    new_inst = _do_pass(i, info, obj)
                    if new_inst is not None:
                        new_child.append(new_inst)
            else:
                obj = PassObject.pack(lvl+1, tag, parent_list)
                new_child = _do_pass(child, info, obj)
                if new_child is None:
                    return None
            new_children.append(new_child)
    new_inst = inst.clone(new_children)
    return new_inst


def transform_func_after_verifier(bpf, info, more):
    """
    Some of the transformations like SEND functions are done after the verifier
    pass. Verifier pass marks which variables are using the BPF context (which
    are on the packet). This pass uses these information.

    e.g., to check if it is needed to copy data from a buffer to
    the packet or it is already on the packet.
    """
    global declare_at_top_of_func
    declare_at_top_of_func = []
    with set_current_func(None):
        res = _do_pass(bpf, info, more)
    if declare_at_top_of_func:
        for inst in declare_at_top_of_func:
            res.children.insert(0, inst)
    declare_at_top_of_func = []

    for func in Function.directory.values():
        if func.is_used_in_bpf_code:
            with set_current_func(func):
                with info.sym_tbl.with_func_scope(current_function.name):
                    func.body = _do_pass(func.body, info, PassObject())
                    if declare_at_top_of_func:
                        for inst in declare_at_top_of_func:
                            func.body.children.insert(0, inst)
                    declare_at_top_of_func = []
    return res
