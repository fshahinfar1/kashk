import clang.cindex as clang
from utility import generate_struct_with_fields, indent
from data_structure import MyType, BASE_TYPES
from instruction import *
from log import debug
from bpf_code_gen import gen_code


class BPF_PROG:
    def __init__(self):
        self.declarations = []
        self.headers = [
                '#include <linux/bpf.h>',
                '#include <bpf/bpf_helpers.h>',
                '#include <bpf/bpf_endian.h>',
                '#include <sys/types.h>',
                '#include <sys/socket.h>',
                '#include <linux/in.h>',
                ]
        self.main_code = None
        self.license = 'GPL'
        self.ctx = 'ctx'

    def add_declaration(self, text):
        self.declarations.append(text)

    def set_bpf_context_struct_sym_tbl(self, sym_tbl):
        raise Exception('Not implemented!')

    def gen_code(self, info):
        raise Exception('Not implemented!')

    def set_code(self, code):
        raise Exception('Not implemented!')

    def get_pkt_buf(self):
        raise Exception('Not implemented!')

    def get_pkt_size(info):
        raise Exception('Not implemented!')

    def add_args_to_scope(self, scope):
        raise Exception('Not implemented!')

    def send(self, buf, write_size, info):
        raise Exception('Not implemented!')

    def adjust_pkt(self, final_size):
        raise Exception('Not implemented!');

    def get_drop(self):
        raise Exception('Not implemented!')

    def get_pass(self):
        raise Exception('Not implemented!')

    def get_send(self):
        raise Exception('Not implemented!')



class XDP_PROG(BPF_PROG):

    def __init__(self):
        super().__init__()
        self.ctx = 'xdp'

    def set_bpf_context_struct_sym_tbl(self, sym_tbl):
        struct_name = 'xdp'
        T = MyType.make_simple('xdp_md', clang.TypeKind.RECORD)
        scope_key = f'class_{T.spelling}'
        sym_tbl.global_scope.insert_entry(struct_name, T, clang.CursorKind.CLASS_DECL, None)
        with sym_tbl.new_scope() as scope:
            sym_tbl.scope_mapping[scope_key] = scope
            U32 = BASE_TYPES[clang.TypeKind.UINT]
            sym_tbl.insert_entry('data', U32, clang.CursorKind.FIELD_DECL, None)
            sym_tbl.insert_entry('data_end', U32, clang.CursorKind.FIELD_DECL, None)

    def set_code(self, code):
        self.main_code = code

    def gen_code(self, info):
        code,_ = gen_code(self.main_code, info)
        code = indent(code, 1)

        text = f'''
SEC("xdp")
int xdp_prog(struct xdp_md *xdp)
{{
{code}
}}
'''
        return text

    def get_pkt_buf(self):
        xdp = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        xdp.name = 'xdp'
        xdp.type = MyType.make_pointer(MyType.make_simple('xdp_md', clang.TypeKind.RECORD))

        ref = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        ref.name = 'data'
        ref.type = BASE_TYPES[clang.TypeKind.UINT]
        ref.owner.append(xdp)

        cast1 = Cast()
        cast1.castee.add_inst(ref)
        cast1.cast_type = BASE_TYPES[clang.TypeKind.ULONGLONG]
        cast2 = Cast()
        cast2.castee.add_inst(cast1)
        cast2.cast_type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
        return cast2

    def get_pkt_size(info):
        return Literal(f'((__u64)xdp->data_end - (__u64)xdp->data)', CODE_LITERAL)

    def add_args_to_scope(self, scope):
        T = MyType.make_pointer(MyType.make_simple('xdp_md', clang.TypeKind.RECORD))
        scope.insert_entry('xdp', T, clang.CursorKind.PARM_DECL, None)

    def send(self, buf, write_size, info):
        is_size_integer = write_size.kind == clang.CursorKind.INTEGER_LITERAL
        if is_size_integer:
            memcpy = 'memcpy'
        else:
            # TODO: I need to check that BPF MEMCPY succeeds
            memcpy = 'bpf_memcpy'
            func = Function.directory[memcpy]
            func.is_used_in_bpf_code = True
            info.prog.declarations.insert(0, func)

        write_size,_ = gen_code([write_size], info, ARG)
        code = f'''
{{
  int delta = {write_size} - ((__u64)xdp->data_end - (__u64)xdp->data);
  bpf_xdp_adjust_tail(xdp, delta);
}}
if (((void *)(__u64)xdp->data + {write_size}) > (void *)(__u64)xdp->data_end) {{
  return SK_DROP;
}}
{memcpy}((void *)(__u64)xdp->data, {buf}, {write_size});
return XDP_TX;
'''
        inst = Literal(code, CODE_LITERAL)
        return inst

    def adjust_pkt(self, final_size):
        return f'''
{{
  int delta = {final_size} - ((__u64)xdp->data_end - (__u64)xdp->data);
  bpf_xdp_adjust_tail(xdp, delta);
}}
'''

    def get_drop(self):
        return 'XDP_DROP'

    def get_pass(self):
        return 'XDP_PASS'

    def get_send(self):
        return 'XDP_TX'


class SK_SKB_PROG(BPF_PROG):
    def __init__(self):
        super().__init__()
        self.connection_state = []
        self.parser_code = None
        self.verdict_code = None
        self.headers += [
                # headers
                '#include <linux/tcp.h>',
                ]

        bpf_parser = Block(BODY)
        bpf_parser.add_inst(Literal('return skb->len;', CODE_LITERAL))
        self.parser_code = bpf_parser
        self.ctx = 'skb'

    def set_bpf_context_struct_sym_tbl(self, sym_tbl):
        struct_name = '__sk_buff'
        T = MyType.make_simple(struct_name, clang.TypeKind.RECORD)
        scope_key = f'class_{T.spelling}'
        sym_tbl.insert_entry(scope_key, T, clang.CursorKind.CLASS_DECL, None)
        with sym_tbl.new_scope() as scope:
            sym_tbl.scope_mapping[scope_key] = scope
            # # map __class__ identifier to the class representing current scope -
            # e = info.sym_tbl.insert_entry('__class__', None, clang.CursorKind.CLASS_DECL, None)
            # # override the name form __class__ to actual class name
            # e.name = struct_name
            # # -------------------------------------------------------------------
            U32 = BASE_TYPES[clang.TypeKind.UINT]
            sym_tbl.insert_entry('data', U32, clang.CursorKind.FIELD_DECL, None)
            sym_tbl.insert_entry('data_end', U32, clang.CursorKind.FIELD_DECL, None)
            sym_tbl.insert_entry('len', U32, clang.CursorKind.FIELD_DECL, None)

    def set_code(self, code):
        self.verdict_code = code

    def add_connection_state(self, state):
        self.connection_state.append(state)

    def _per_connection_state(self):
        return ([
                '/* Put state of each socket in this struct (This will be used in sockops.h as',
                ' * part of per socket metadata) */',
                generate_struct_with_fields('connection_state', self.connection_state)+';',
                '#include "my_bpf/sockops.h"',
                ])


    def _load_connection_state(self):
        return '''struct sock_context *sock_ctx;

if (skb->sk == NULL) {
  bpf_printk("The socket reference is NULL");
  return SK_DROP;
}
sock_ctx = bpf_sk_storage_get(&sock_ctx_map, skb->sk, NULL, 0);
if (!sock_ctx) {
  bpf_printk("Failed to get socket context!");
  return SK_DROP;
}
'''

    def _pull_packet_data(self):
        return '''if (bpf_skb_pull_data(skb, skb->len) != 0) {
  bpf_printk("Parser: Failed to load message data");
  return SK_DROP;
}
'''

    def _parser_prog(self, body):
        return ([
                'SEC("sk_skb/stream_parser")',
                'int parser(struct __sk_buff *skb)',
                '{',
                ]
                + body
                + ['}']
                )

    def _verdict_prog(self, body):
        return ([
                'SEC("sk_skb/stream_verdict")',
                'int verdict(struct __sk_buff *skb)',
                '{',
                ]
                + body
                + ['}']
                )

    def gen_code(self, info):
        per_conn = info.prog._per_connection_state()
        parser_code, _ = gen_code(self.parser_code, info)
        parser_code = indent(parser_code, 1)
        verdict_code, _ = gen_code(self.verdict_code, info)
        verdict_code = (self._pull_packet_data() + self._load_connection_state() + verdict_code)
        verdict_code = indent(verdict_code, 1)

        return '\n'.join(info.prog._parser_prog([per_conn] + [''] + [parser_code]) + [''] + info.prog._verdict_prog([verdict_code]))

    def get_pkt_buf(self):
        return f'(void *)(__u64)skb->data;\n'

    def get_pkt_size(info):
        return Literal(f'skb->len', CODE_LITERAL)

    def add_args_to_scope(self, scope):
        T = MyType.make_pointer(MyType.make_simple('__sk_skb', clang.TypeKind.RECORD))
        scope.insert_entry('skb', T, clang.CursorKind.PARM_DECL, None)

    def send(self, buf, write_size, info):
        is_size_integer = write_size.kind == clang.CursorKind.INTEGER_LITERAL
        if is_size_integer:
            memcpy = 'memcpy'
        else:
            # TODO: I need to check that BPF MEMCPY succeeds
            memcpy = 'bpf_memcpy'
            func = Function.directory[memcpy]
            func.is_used_in_bpf_code = True
            info.prog.declarations.insert(0, func)

        write_size,_ = gen_code(write_size, info)
        skb = 'skb'
        code = [
            f'__adjust_skb_size({skb}, {write_size});',
            f'if (((void *)(__u64){skb}->data + {write_size})  > (void *)(__u64){skb}->data_end) {{',
            f'  return SK_DROP;',
            '}',
            f'{memcpy}((void *)(__u64){skb}->data, {buf}, {write_size});',
            f'return bpf_sk_redirect_map({skb}, &sock_map, sock_ctx->sock_map_index, 0);',
            ]
        text = '\n'.join(code)
        inst = Literal(text, CODE_LITERAL)
        return inst

    def adjust_pkt(self, final_size):
        return f'__adjust_skb_size(skb, {final_size});'

    def get_drop(self):
        return 'SK_DROP'

    def get_pass(self):
        return 'SK_PASS'

    def get_send(self):
        raise Exception('not implemented')
