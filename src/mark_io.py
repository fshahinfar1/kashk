"""
The goal of this module is to map socket programs read/write/... operations to
BPF supported instructions
"""

from data_structure import *
from dfs import DFSPass
from utility import skip_unexposed_stmt
from prune import READ_PACKET, WRITE_PACKET, COROUTINE_FUNC_NAME
from bpf_code_gen import gen_code

MODULE_TAG = '[IO]'

def _get_all_read(block):
    """
    Get all the read instructions under the cursor
    """
    result = []
    d = DFSPass(block)
    for c,_ in d:
        # c is of type Instruction, ...
        if c.kind == clang.CursorKind.CALL_EXPR:
            func_name = c.name
            if func_name in COROUTINE_FUNC_NAME:
                # These functions are for coroutine and make things complex
                continue

            if func_name in READ_PACKET:
                result.append(c)
                continue
        d.go_deep()
    return result


def _do_mark_read(r, info):
    args = list(r.get_arguments())
    buf_arg = None
    buf_sz = None

    func_name = r.name
    if func_name == 'async_read_some':
        buf_arg = skip_unexposed_stmt(args[0])
    elif func_name == 'read':
        buf_arg = skip_unexposed_stmt(args[1])
        buf_sz = skip_unexposed_stmt(args[2])
    elif func_name == 'recvfrom':
        # NOTE: what happens if the server respond on another socket ?
        buf_arg = skip_unexposed_stmt(args[1])
        buf_sz = skip_unexposed_stmt(args[2])

    pkt_buf = PacketBuffer(None)
    pkt_buf.size_cursor, _ = gen_code([buf_sz], info)
    pkt_buf.name, _ = gen_code([buf_arg], info)
    r.rd_buf = pkt_buf
    debug('Read buffer:', pkt_buf.name, pkt_buf.size_cursor, r)


def _mark_read_insts(bpf, info):
    reads = _get_all_read(bpf)
    for r in reads:
        _do_mark_read(r, info)


def _mark_write_insts(bpf, info):
    return
    writes = get_all_send(ev_loop)
    assert len(writes) <= 1, f'I currently expect only one send system call (count found: {len(writes)})'
    for c in writes:
        # TODO: this code is not going to work. it is so specific
        args = list(c.get_arguments())

        buf_arg = None
        buf_sz = None

        if c.spelling == 'async_write':
            buf_arg = args[1]
        elif c.spelling == 'async_write_some':
            buf_arg = args[0]
        elif c.spelling == 'write':
            buf_arg = args[1]
            buf_sz = args[2]

        while buf_arg.kind == clang.CursorKind.UNEXPOSED_EXPR:
            children = list(buf_arg.get_children())
            assert len(children) == 1, f'len(children) == {len(children)}'
            buf_arg = children[0]


        if buf_arg.kind == clang.CursorKind.CALL_EXPR:
            args = list(buf_arg.get_arguments())
            buf_def = args[0].get_definition()
            info.wr_buf = PacketBuffer(buf_def)
            if len(args) == 2:
                buf_sz = args[1]
                info.wr_buf.size_cursor = gather_instructions_from(buf_sz, info)
            else:
                # TODO: I need to some how know the size and I might not know
                # it! I can try to find the underlying array. But what if it is
                # not an array?
                error('I need to know the buffer size')
                info.wr_buf.size_cursor = [Literal('2048', clang.CursorKind.INTEGER_LITERAL)]
        else:
            buf_def = buf_arg.get_definition()
            remove_def = buf_def
            # info.remove_cursor.add(remove_def.get_usr())
            if buf_def.kind == clang.CursorKind.CALL_EXPR:
                buf_def = next(buf_def.get_children())
                args = list(buf_def.get_arguments())
                buf_def = args[0].get_definition()
                buf_sz = args[1]
                info.wr_buf = PacketBuffer(buf_def)
                info.wr_buf.size_cursor = gather_instructions_from(buf_sz, info)
            else:
                info.wr_buf = PacketBuffer(buf_def)
                if buf_sz is None:
                    children = list(buf_def.get_children())
                    if len(children) > 0:
                        init = children[0]
                        if init.kind == clang.CursorKind.CALL_EXPR:
                            args = list(init.get_arguments())
                            buf_def = args[0].get_definition()
                            buf_sz = args[1]
                            info.wr_buf = PacketBuffer(buf_def)
                            info.wr_buf.size_cursor = gather_instructions_from(buf_sz, info)
                        else:
                            raise Exception('')
                    else:
                        raise Exception('')
                else:
                    info.wr_buf.size_cursor = gather_instructions_from(buf_sz, info)

def _do_pass(bpf, info):
    _mark_read_insts(bpf, info)
    _mark_write_insts(bpf, info)

def mark_io(bpf, info):
    # Apply it on the main body ...
    _do_pass(bpf, info)
    # ... and all the other functions
    for func in Function.directory.values():
        _do_pass(func.body, info)
