import clang.cindex as clang
from utility import generate_struct_with_fields, indent
from data_structure import MyType, BASE_TYPES
from instruction import Block, BODY, Literal, CODE_LITERAL
from log import debug
from bpf_code_gen import gen_code


class BPF_PROG:
    def __init__(self):
        self.declarations = []
        self.headers = [
                '#include <linux/bpf.h>',
                '#include <bpf/bpf_helpers.h>',
                '#include <bpf/bpf_endian.h>',
                ]
        self.main_code = []
        self.license = 'GPL'

    def add_declaration(self, text):
        self.declarations.append(text)

    def set_bpf_context_struct_sym_tbl(self, sym_tbl):
        raise Exception('Not implemented!')

    def gen_code(self, info):
        raise Exception('Not implemented!')

    def set_code(self, code):
        raise Exception('Not implemented!')


class XDP_PROG(BPF_PROG):
    def __init__(self):
        super().__init__()

    def set_bpf_context_struct_sym_tbl(self, sym_tbl):
        struct_name = 'xdp'
        T = MyType.make_simple('xdp_md', clang.TypeKind.RECORD)
        scope_key = f'class_{T.spelling}'
        sym_tbl.insert_entry(struct_name, T, clang.CursorKind.CLASS_DECL, None)
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
SEC('xdp')
int xdp_prog(struct xdp_md *xdp)
{{
{code}
}}
'''
        return text


class SK_SKB_PROG(BPF_PROG):
    def __init__(self):
        super().__init__()
        self.connection_state = []
        self.parser_code = None
        self.verdict_code = None
        self.headers += [
                # headers
                '#include <sys/types.h>',
                '#include <sys/socket.h>',
                '#include <linux/tcp.h>',
                ]

        bpf_parser = Block(BODY)
        bpf_parser.add_inst(Literal('return skb->len;', CODE_LITERAL))
        self.parser_code = bpf_parser

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
