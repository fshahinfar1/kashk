import clang.cindex as clang
from utility import generate_struct_with_fields
from data_structure import MyType
from log import debug


class SK_SKB_PROG:
    def __init__(self):
        self.connection_state = []
        self._decs = set()
        self.declarations = []
        self.parser_code = []
        self.verdict_code = []
        self.headers = [
                # headers
                '#include <sys/types.h>',
                '#include <sys/socket.h>',
                '#include <linux/tcp.h>',
                '#include <linux/bpf.h>',
                '#include <bpf/bpf_helpers.h>',
                '#include <bpf/bpf_endian.h>',
                ]
        self.license = 'GPL'

    def set_bpf_context_struct_sym_tbl(self, sym_tbl):
        struct_name = '__sk_buff'
        T = MyType()
        T.spelling = f'struct {struct_name}'
        T.kind = clang.TypeKind.RECORD
        scope_key = f'class_{T.spelling}'
        sym_tbl.insert_entry(scope_key, T, clang.CursorKind.CLASS_DECL, None)
        with sym_tbl.new_scope() as scope:
            sym_tbl.scope_mapping[scope_key] = scope
            # # map __class__ identifier to the class representing current scope -
            # e = info.sym_tbl.insert_entry('__class__', None, clang.CursorKind.CLASS_DECL, None)
            # # override the name form __class__ to actual class name
            # e.name = struct_name 
            # # -------------------------------------------------------------------
            T = MyType()
            T.spelling = '__u32'
            T.kind = clang.TypeKind.UINT
            sym_tbl.insert_entry('data', T, clang.CursorKind.FIELD_DECL, None)
            sym_tbl.insert_entry('data_end', T, clang.CursorKind.FIELD_DECL, None)

    def add_connection_state(self, state):
        self.connection_state.append(state)

    def add_declaration(self, text):
        if text not in self._decs:
            self._decs.add(text)
            self.declarations.append(text)

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

