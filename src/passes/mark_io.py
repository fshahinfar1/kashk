"""
The goal of this module is to map socket programs read/write/... operations to
BPF supported instructions
"""

from contextlib import contextmanager

from data_structure import *
from instruction import Literal, CODE_LITERAL, Ref
from dfs import DFSPass
from utility import skip_unexposed_stmt, find_elems_of_kind
from prune import READ_PACKET, WRITE_PACKET, COROUTINE_FUNC_NAME
from code_gen import gen_code


MODULE_TAG = '[IO]'
current_function = None
has_processed = set()


@contextmanager
def _set_current_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield None
    finally:
        current_function = tmp


def _do_mark_read(r, info):
    args = list(r.get_arguments())
    buf_arg = None
    buf_sz = None

    func_name = r.name
    if func_name == 'async_read_some':
        buf_arg = skip_unexposed_stmt(args[0])
        # TODO: assume a size for the buffer
        buf_sz = Literal('1024', clang.CursorKind.INTEGER_LITERAL)
    elif func_name == 'read' or func_name == 'recv':
        buf_arg = skip_unexposed_stmt(args[1])
        buf_sz = skip_unexposed_stmt(args[2])
    elif func_name == 'recvfrom':
        # NOTE: what happens if the server respond on another socket ?
        buf_arg = skip_unexposed_stmt(args[1])
        buf_sz = skip_unexposed_stmt(args[2])
    elif func_name == 'recvmsg':
        raise Exception('it is not implemented yet')
    else:
        raise Exception('it is not implemented yet')

    pkt_buf = PacketBuffer(None)
    pkt_buf.size_cursor, _ = gen_code([buf_sz], info)
    pkt_buf.name, _ = gen_code([buf_arg], info)
    pkt_buf.ref = buf_arg
    pkt_buf.size_ref = buf_sz
    r.rd_buf = pkt_buf

    # TODO: it is a hack for finding the variable declaration
    if isinstance(buf_arg, Ref):
        current_func_name = current_function.name if current_function else '[[main]]'
        names = info.read_decl.setdefault(current_func_name, set())
        names.add(buf_arg.name)
    # debug('Read buffer:', pkt_buf.name, pkt_buf.size_cursor, r)


def _mark_read_insts(bpf, info):
    # reads = _get_all_read(bpf)
    reads = find_elems_of_kind(bpf, clang.CursorKind.CALL_EXPR, lambda i: i.name in READ_PACKET)
    if reads and current_function:
        current_function.calls_recv = True
    for r in reads:
        _do_mark_read(r, info)


def _do_mark_write(w, info):
    args = list(w.get_arguments())
    buf_arg = None
    buf_sz = None

    func_name = w.name
    if func_name == 'async_write':
        buf_arg = skip_unexposed_stmt(args[1])
        # TODO: assume a size for the buffer
        buf_sz = Literal('1024', clang.CursorKind.INTEGER_LITERAL)
    elif func_name == 'async_write_some':
        buf_arg = skip_unexposed_stmt(args[0])
        # TODO: assume a size for the buffer
        buf_sz = Literal('1024', clang.CursorKind.INTEGER_LITERAL)
    elif func_name in ('write', 'send', 'sendto'):
        buf_arg = skip_unexposed_stmt(args[1])
        buf_sz = skip_unexposed_stmt(args[2])
    elif func_name == 'sendmsg':
        error('sendmsg is not supported yet')
        # buf_arg = skip_unexposed_stmt(args[1])
        # assert isinstance(buf_arg, Ref)
        # buf_arg = buf_arg.get_ref_field('', info)
        buf_arg = Literal('<buf>', CODE_LITERAL)
        buf_sz = Literal('1024', clang.CursorKind.INTEGER_LITERAL)

    pkt_buf = PacketBuffer(None)
    pkt_buf.size_cursor = buf_sz
    pkt_buf.name, _ = gen_code([buf_arg], info)
    pkt_buf.ref = buf_arg
    pkt_buf.size_ref = buf_sz
    w.wr_buf = pkt_buf
    # debug('Write buffer:', pkt_buf.name, pkt_buf.size_cursor, w)


def _mark_write_insts(bpf, info):
    writes = find_elems_of_kind(bpf, clang.CursorKind.CALL_EXPR, lambda i: i.name in WRITE_PACKET)
    if writes and current_function:
        current_function.calls_send = True
    for w in writes:
        _do_mark_write(w, info)


def _do_pass(bpf, info):
    _mark_read_insts(bpf, info)
    _mark_write_insts(bpf, info)
    # Check if this function invokes any function that might call recv/write
    calls = find_elems_of_kind(bpf, clang.CursorKind.CALL_EXPR)
    for call in calls:
        func = call.get_function_def()
        if func is None:
            continue
        if not func.is_empty() and func.name not in has_processed:
            with _set_current_func(func):
                _do_pass(func.body, info)
                has_processed.add(func.name)
        if current_function is not None:
            current_function.calls_recv = current_function.calls_recv or func.calls_recv
            current_function.calls_send = current_function.calls_send or func.calls_send


def mark_io(bpf, info):
    assert len(has_processed) == 0, 'This pass should only be invoked once'
    # Apply it on the main body ...
    _do_pass(bpf, info)
    # ... and all the other functions
    for func in Function.directory.values():
        if func.is_used_in_bpf_code and func.name not in has_processed:
            with _set_current_func(func):
                _do_pass(func.body, info)
                has_processed.add(func.name)
