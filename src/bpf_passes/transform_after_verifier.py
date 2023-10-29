import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *
from prune import WRITE_PACKET
from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from bpf_passes.transform_vars import SEND_FLAG_NAME
from helpers.bpf_ctx_helper import is_bpf_ctx_ptr, is_value_from_bpf_ctx


MODULE_TAG = '[2nd Transform]'
cb_ref = CodeBlockRef()
current_function = None
_has_processed_func = set()

def _get_fail_ret_val():
    if current_function is None:
        return 'XDP_DROP'
    elif current_function.return_type.spelling == 'void':
        return ''
    else:
        return f'({current_function.return_type.spelling})0'

# TODO: why I have to return functions! What am I doing? :)
def _get_ret_inst():
    ret = Instruction()
    ret.kind = clang.CursorKind.RETURN_STMT
    if current_function is None:
        ret.body = [Literal('XDP_DROP', CODE_LITERAL)]
    elif current_function.return_type.spelling != 'void':
        ret.body = [Literal(f'({current_function.return_type.spelling})0', CODE_LITERAL)]
    else:
        ret.body = []
    return ret


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
        copy_inst = info.prog.send(buf, write_size, info, ret=False, failure=_get_fail_ret_val(), do_copy=should_copy)
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
        inst = _get_ret_inst()
    return inst


def _process_call_inst(inst, info):
    if inst.name in WRITE_PACKET:
        return _process_write_call(inst, info)
    return inst


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        return _process_call_inst(inst,info)
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
    global current_function
    current_function = None
    res = _do_pass(bpf, info, more)

    for func in Function.directory.values():
        if func.is_used_in_bpf_code:
            current_function = func
            with info.sym_tbl.with_func_scope(current_function.name):
                func.body = _do_pass(func.body, info, PassObject())
            current_function = None
    return res
