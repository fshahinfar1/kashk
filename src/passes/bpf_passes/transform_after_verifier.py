import clang.cindex as clang
from contextlib import contextmanager

from log import error, debug, report
from data_structure import *
from instruction import *
from my_type import MyType
from prune import WRITE_PACKET, KNOWN_FUNCS
from template import malloc_lookup
from code_gen import gen_code
from passes.pass_obj import PassObject
from passes.update_original_ref import set_original_ref
from passes.clone import clone_pass
from helpers.bpf_ctx_helper import is_bpf_ctx_ptr, is_value_from_bpf_ctx
from helpers.instruction_helper import (get_ret_inst, get_ret_value_text)
from helpers.cache_helper import generate_cache_lookup, generate_cache_update
from var_names import SEND_FLAG_NAME
import template


MODULE_TAG = '[2nd Transform]'
cb_ref = CodeBlockRef()
parent_block = CodeBlockRef()
current_function = None
_has_processed_func = set()
declare_at_top_of_func = None
# Skip until the cache END
skip_to_end = None
_changed_type = None

def _is_known_integer(inst):
    if (isinstance(inst, Literal) or
        (inst.kind == clang.CursorKind.UNARY_OPERATOR
            and inst.op == 'sizeof')):
        return True

    if inst.kind == clang.CursorKind.BINARY_OPERATOR:
        lhs = inst.lhs.children[0]
        rhs = inst.rhs.children[0]
        if inst.op == '=':
            return _is_known_integer(rhs)
        return _is_known_integer(lhs) and _is_known_integer(rhs)
    return False


def _set_skip(val):
    global skip_to_end
    skip_to_end = val


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


_stack_large_obj = 0
def _get_stack_obj_name():
    global _stack_large_obj
    _stack_large_obj += 1
    return f'stack_obj_{_stack_large_obj}'


def _rename_func_to_a_known_one(inst, info, target_name):
    inst.name = target_name
    # Mark the function used
    func = inst.get_function_def()
    assert func is not None, 'We should have a Function object for each known function'
    if not func.is_used_in_bpf_code:
        func.is_used_in_bpf_code = True
        info.prog.declarations.insert(0, func)
    # debug(MODULE_TAG, 'Add func:', func.name)
    inst.set_modified(InstructionColor.KNOWN_FUNC_IMPL)
    return inst


def _get_upper_bound_for(repeat, size_argum):
    max_bound = repeat
    if max_bound is None:
        if size_argum is not None and _is_known_integer(size_argum):
            # Try to guess the max bound from the size parameter
            max_bound = size_argum
        else:
            error('the operation should have annotation declaring max number of iterations')
            max_bound = 32
    return max_bound


def _known_function_substitution(inst, info, more):
    """
    Replace some famous functions with implementations that work in BPF
    @returns a tuple. First element is a instruction. Second element is a
        boolean. The boolean determines if the instruciton is the return value
        of the function or not.
    """
    blk = cb_ref.get(BODY)
    match inst.name:
        case 'free':
            return None, False
        case 'strlen':
            max_bound = _get_upper_bound_for(inst.repeat, None)
            s1 = inst.args[0]
            tmp_insts, tmp_decl, tmp_res = template.strlen(s1, max_bound, info,
                    current_function)
            declare_at_top_of_func.extend(tmp_decl)
            blk.extend(tmp_insts)
            set_original_ref(tmp_insts, info, inst.original)
            tmp_insts[1].removed.append(inst)
            return tmp_res, True
        case 'strncmp':
            assert len(inst.args) == 3
            s1 = inst.args[0]
            s2 = inst.args[1]
            size = inst.args[2]
            max_bound = _get_upper_bound_for(inst.repeat, size)

            if s1.type is None or s2.type is None:
                breakpoint()
            tmp_insts, tmp_decl, tmp_res = template.strncmp(s1, s2, size,
                    max_bound, info, current_function)
            declare_at_top_of_func.extend(tmp_decl)
            blk.extend(tmp_insts)
            set_original_ref(tmp_insts, info, inst.original)
            tmp_insts[1].removed.append(inst)
            return tmp_res, True
        case 'strcmp':
            assert len(inst.args) == 2
            s1 = inst.args[0]
            s2 = inst.args[1]
            max_bound = _get_upper_bound_for(inst.repeat, None)
            size = Literal(str(max_bound), clang.CursorKind.INTEGER_LITERAL)
            tmp_insts, tmp_decl, tmp_res = template.strncmp(s1, s2, size, max_bound,
                    info, current_function)
            declare_at_top_of_func.extend(tmp_decl)
            blk.extend(tmp_insts)
            set_original_ref(tmp_insts, info, inst.original)
            tmp_insts[1].removed.append(inst)
            return tmp_res, True
        case 'strncpy':
            assert len(inst.args) == 3, 'Assumption on the number of arguments'
            s1 = inst.args[0]
            s2 = inst.args[1]
            size = inst.args[2]
            max_bound = _get_upper_bound_for(inst.repeat, size)
            tmp_insts, tmp_decl, tmp_res = template.strncpy(s1, s2, size,
                    max_bound, info, current_function)
            declare_at_top_of_func.extend(tmp_decl)
            blk.extend(tmp_insts)
            set_original_ref(tmp_insts, info, inst.original)
            tmp_insts[0].removed.append(inst)
            return tmp_res, True
        case 'strcpy':
            assert len(inst.args) == 2
            s1 = inst.args[0]
            s2 = inst.args[1]
            max_bound = _get_upper_bound_for(inst.repeat, None)
            size = Literal(str(max_bound), clang.CursorKind.INTEGER_LITERAL)
            tmp_insts, tmp_decl, tmp_res = template.strncpy(s1, s2, size,
                    max_bound, info, current_function)
            declare_at_top_of_func.extend(tmp_decl)
            blk.extend(tmp_insts)
            set_original_ref(tmp_insts, info, inst.original)
            tmp_insts[0].removed.append(inst)
            return tmp_res, True
        case 'malloc':
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
            info.sym_tbl.current_scope = info.sym_tbl.sk_state_scope
            value_type.update_symbol_table(info.sym_tbl)
            info.sym_tbl.current_scope = __scope
            # report('Declare', value_type, 'as malloc object')

            # Define the map
            m = BPFMap.build_arr_map(map_name, value_type.type, 1)
            m.is_used_in_bpf_code = True
            info.prog.add_declaration(m)
            # report('Declare map', m, 'for malloc')

            # Look the malloc map
            lookup_inst, tmp_decl, ref = malloc_lookup(name, info, current_function)
            declare_at_top_of_func.extend(tmp_decl)
            blk.extend(lookup_inst)
            set_original_ref(lookup_inst, info, inst.original)
            return ref, True
        case 'memcpy':
            assert len(inst.args) == 3
            size = inst.args[2]
            is_constant = _is_known_integer(size)
            if is_constant:
                # No change is needed the builtin memcpy would work
                return inst, False
            max_bound = _get_upper_bound_for(inst.repeat, size)
            assert max_bound is not None, 'The variable memcpy should have annotation declaring max number of iterations'
            dst = inst.args[0]
            src = inst.args[1]
            tmp_insts, decl, tmp_res = template.variable_memcpy(dst, src, size,
                    max_bound, info, current_function)
            declare_at_top_of_func.extend(decl)
            blk.extend(tmp_insts)
            set_original_ref(tmp_insts, info, inst.original)
            tmp_insts[0].removed.append(inst)
            return tmp_res, True
        case ['ntohs' | 'ntohl' | 'htons' | 'htonl']:
            inst.name = 'bpf_'+inst.name
            return inst, False
        case 'htonll':
            inst.name = 'bpf_cpu_to_be64'
            return inst, False
        case 'ntohll':
            inst.name = 'bpf_be64_to_cpu'
            return inst, False
        case 'printk':
            inst.name = 'bpf_printk'
            return inst, False
    error(f'Known function {inst.name} is not implemented yet')
    return inst, False


def _process_write_call(inst, info, more):
    if inst.wr_buf.size_cursor is None:
        write_size = Literal('<UNKNOWN WRITE BUF SIZE>', CODE_LITERAL)
    else:
        write_size = inst.wr_buf.size_cursor
    ref = inst.wr_buf.ref
    should_copy = not is_bpf_ctx_ptr(ref, info)
    blk = cb_ref.get(BODY)
    if current_function is None:
        # On the main BPF program. feel free to return the verdict value
        insts, decl = info.prog.send(ref, write_size, info, current_function,
                do_copy=should_copy)
        blk.extend(insts)
        declare_at_top_of_func.extend(decl)
        set_original_ref(insts, info, inst.original)
        new_inst = insts[-1]
        new_inst.set_modified(InstructionColor.REMOVE_WRITE)
        new_inst.removed.append(inst)

        parent = parent_block.get(BODY)
        last_inst_block = parent.children[-1]
        _set_skip(last_inst_block)
        return None # remove the write call
    else:
        # On a function which is not the main. Do not return
        copy_inst, decl = info.prog.send(ref, write_size, info,
                current_function, ret=False, do_copy=should_copy)
        declare_at_top_of_func.extend(decl)
        # set the flag
        flag_ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        flag_ref.name = SEND_FLAG_NAME
        flag_ref.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
        deref = UnaryOp(None)
        deref.child.add_inst(flag_ref)
        deref.op = '*'
        one = Literal('1', clang.CursorKind.INTEGER_LITERAL)
        set_flag = BinOp.build(deref, '=', one)
        set_flag.set_modified(InstructionColor.EXTRA_MEM_ACCESS)
        # add it to the body
        blk.extend(copy_inst)
        set_original_ref(copy_inst, info, inst.original)
        blk.append(set_flag)
        set_original_ref(set_flag, info, inst.original)
        # Return from this point to the BPF main
        new_inst = get_ret_inst(current_function, info)
        new_inst.set_modified(InstructionColor.REMOVE_WRITE)
        new_inst.removed.append(inst)
        blk.append(new_inst)
        return None
    return None


def _process_call_inst(inst, info, more):
    if inst.name in WRITE_PACKET:
        return _process_write_call(inst, info, more)
    elif inst.name in KNOWN_FUNCS:
        tmp, is_ret_val = _known_function_substitution(inst, info, more)
        if is_ret_val and more.ctx == BODY:
            # Discard the return value of the function
            return None
        return tmp
    return inst


def _process_annotation(inst, info):
    if inst.ann_kind == Annotation.ANN_CACHE_BEGIN_UPDATE:
        blk = cb_ref.get(BODY)
        new_inst, to_be_declared = generate_cache_update(inst, blk, current_function, info)
        declare_at_top_of_func.extend(to_be_declared)
        return new_inst
    elif inst.ann_kind == Annotation.ANN_CACHE_END_UPDATE:
        return None
    elif inst.ann_kind == Annotation.ANN_CACHE_BEGIN:
        blk = cb_ref.get(BODY)
        parent_node = parent_block.get(BODY)
        parent_children = parent_node.get_children()
        new_inst, to_be_declared = generate_cache_lookup(inst, blk,
                current_function, parent_children, info)
        declare_at_top_of_func.extend(to_be_declared)
        return new_inst
    elif inst.ann_kind == Annotation.ANN_CACHE_END:
        return None
    # Remove annotation
    return None


def _process_var_decl(inst, info):
    # NOTE: these variables are defined on the stack memory
    # TODO: I need to track the total memory allocated on the stack and not
    # just the size of each object. But for now let's just move huge objects to
    # the map.
    if inst.type.mem_size <= 255:
        return inst
    debug('Moving large vars to BPF map is a work in progress!', tag=MODULE_TAG)
    raise Exception(f'Large variable declared on stack! {inst}')
    debug(MODULE_TAG, f'moving {inst.name}:{inst.type.spelling} to BPF map')
    debug(MODULE_TAG, f'{inst.name}:{inst.type.spelling} ({inst.type.mem_size} bytes)')

    name = _get_stack_obj_name()
    map_name = name + '_map'
    data_field = StateObject(None)
    data_field.name = 'data'
    data_field.type_ref = inst.type
    struct_decl = Record(name, [data_field])
    struct_decl.is_used_in_bpf_code = True
    info.prog.add_declaration(struct_decl)
    # Update symbol table
    __scope = info.sym_tbl.current_scope
    info.sym_tbl.current_scope = info.sym_tbl.sk_state_scope
    struct_decl.update_symbol_table(info.sym_tbl)
    info.sym_tbl.current_scope = __scope
    # Define the BPF map
    m = BPFMap.build_arr_map(map_name, struct_decl.type, 1)
    m.is_used_in_bpf_code = True
    info.prog.add_declaration(m)
    # Lookup the malloc map
    lookup_inst, decl, ref = malloc_lookup(name, info, current_function)
    declare_at_top_of_func.extend(decl)
    blk = cb_ref.get(BODY)
    blk.extend(lookup_inst)
    set_original_ref(lookup_inst, info, inst.original)

    new_type = None
    def _convert_type(t):
        if t.is_array():
            # tmp = _convert_type(t.element_type)
            tmp = t.element_type
            return MyType.make_pointer(tmp)
        elif t.is_record():
            return MyType.make_pointer(t)
        else:
            return t
            # raise Exception('Not implemented yet?', str(t))
    new_type = _convert_type(inst.type)
    new_var_decl = VarDecl.build(inst.name, new_type)
    new_var_decl.update_symbol_table(info.sym_tbl)
    declare_at_top_of_func.append(new_var_decl)
    # blk.append(new_var_decl)
    var_ref = new_var_decl.get_ref()
    casted_ref = Cast.build(UnaryOp.build('&', ref), var_ref.type)
    assign = BinOp.build(var_ref, '=', casted_ref)
    assign.set_modified()
    set_original_ref(assign, info, inst.original)

    _changed_type[var_ref.name] = new_type
    return assign


def _process_ref(inst, info):
    if inst.name not in _changed_type:
        return inst
    new_type = _changed_type[inst.name]
    debug(f'Changing type of {inst.name} to {new_type}', tag=MODULE_TAG)
    new_inst = clone_pass(inst)
    new_inst.type = new_type
    return new_inst


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        return _process_call_inst(inst, info, more)
    elif inst.kind == ANNOTATION_INST:
        return _process_annotation(inst, info)
    elif inst.kind == clang.CursorKind.VAR_DECL:
        return _process_var_decl(inst, info)
    elif inst.kind == clang.CursorKind.DECL_REF_EXPR:
        return _process_ref(inst, info)
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
            # TODO: try to refactor this module into a Pass class
            with parent_block.new_ref(tag, inst):
                if isinstance(child, list):
                    new_child = []
                    for i in child:
                        obj = PassObject.pack(lvl+1, tag, new_child)
                        new_inst = _do_pass(i, info, obj)
                        # Check if we are skipping
                        if skip_to_end is not None:
                            if skip_to_end == i:
                                _set_skip(None)
                            continue
                        if new_inst is not None:
                            new_child.append(new_inst)
                        elif tag != BODY:
                            return None
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
    pass. Verifier pass marks which variables are using the BPF context. This
    pass uses these information e.g., to check if it is needed to copy data
    from a buffer to the packet or it is already on the packet.
    """
    global declare_at_top_of_func
    global _changed_type
    _changed_type = {}
    declare_at_top_of_func = []
    with set_current_func(None):
        res = _do_pass(bpf, info, more)
    if declare_at_top_of_func:
        for inst in declare_at_top_of_func:
            res.children.insert(0, inst)
    declare_at_top_of_func = []
    _changed_type = {}

    for func in Function.directory.values():
        if func.is_used_in_bpf_code:
            with set_current_func(func):
                with info.sym_tbl.with_func_scope(current_function.name):
                    func.body = _do_pass(func.body, info, PassObject())
                    if declare_at_top_of_func:
                        for inst in declare_at_top_of_func:
                            func.body.children.insert(0, inst)
                    declare_at_top_of_func = []
                    _changed_type = {}
    return res
