"""
The goal of this module is to map socket programs read/write/... operations to
BPF supported instructions
"""

from data_structure import *
from dfs import DFSPass
from utility import skip_unexposed_stmt, find_elems_of_kind
from prune import READ_PACKET, WRITE_PACKET, COROUTINE_FUNC_NAME
from bpf_code_gen import gen_code

MODULE_TAG = '[IO]'


def _do_mark_read(r, info):
    args = list(r.get_arguments())
    buf_arg = None
    buf_sz = None

    func_name = r.name
    if func_name == 'async_read_some':
        buf_arg = skip_unexposed_stmt(args[0])
        # TODO: assume a size for the buffer
        buf_sz = Literal('1024', clang.CursorKind.INTEGER_LITERAL)
    elif func_name == 'read':
        buf_arg = skip_unexposed_stmt(args[1])
        buf_sz = skip_unexposed_stmt(args[2])
    elif func_name == 'recvfrom':
        # NOTE: what happens if the server respond on another socket ?
        buf_arg = skip_unexposed_stmt(args[1])
        buf_sz = skip_unexposed_stmt(args[2])
    elif func_name == 'recvmsg':
        raise Exception('it is not implemented yet')

    pkt_buf = PacketBuffer(None)
    pkt_buf.size_cursor, _ = gen_code([buf_sz], info)
    pkt_buf.name, _ = gen_code([buf_arg], info)
    r.rd_buf = pkt_buf
    debug('Read buffer:', pkt_buf.name, pkt_buf.size_cursor, r)


def _mark_read_insts(bpf, info):
    # reads = _get_all_read(bpf)
    reads = find_elems_of_kind(bpf, clang.CursorKind.CALL_EXPR, lambda i: i.name in READ_PACKET)
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
    elif func_name in ('write', 'send'):
        buf_arg = skip_unexposed_stmt(args[1])
        buf_sz = skip_unexposed_stmt(args[2])
    elif func_name == 'sendmsg':
        raise Exception('it is not implemented yet')

    pkt_buf = PacketBuffer(None)
    pkt_buf.size_cursor, _ = gen_code([buf_sz], info)
    pkt_buf.name, _ = gen_code([buf_arg], info)
    w.wr_buf = pkt_buf
    debug('Write buffer:', pkt_buf.name, pkt_buf.size_cursor, w)


def _mark_write_insts(bpf, info):
    writes = find_elems_of_kind(bpf, clang.CursorKind.CALL_EXPR, lambda i: i.name in WRITE_PACKET)
    for w in writes:
        _do_mark_write(w, info)


def _do_pass(bpf, info):
    _mark_read_insts(bpf, info)
    _mark_write_insts(bpf, info)


def mark_io(bpf, info):
    # Apply it on the main body ...
    _do_pass(bpf, info)
    # ... and all the other functions
    for func in Function.directory.values():
        if func.is_used_in_bpf_code:
            _do_pass(func.body, info)
