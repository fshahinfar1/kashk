from bpf import BPF_PROG
from data_structure import MyType, BASE_TYPES, Record, StateObject
from instruction import *
from helpers.instruction_helper import *
from bpf_code_gen import gen_code


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
        self.ctx_type = MyType.make_pointer(MyType.make_simple('struct __sk_skb', clang.TypeKind.RECORD))

    def set_bpf_context_struct_sym_tbl(self, sym_tbl):
        T = self.ctx_type.under_type
        scope_key = f'class_{T.spelling}'
        sym_tbl.global_scope.insert_entry(scope_key, T, clang.CursorKind.CLASS_DECL, None)
        with sym_tbl.new_scope() as scope:
            sym_tbl.scope_mapping[scope_key] = scope
            # # map __class__ identifier to the class representing current scope -
            # e = info.sym_tbl.insert_entry('__class__', None, clang.CursorKind.CLASS_DECL, None)
            # # override the name form __class__ to actual class name
            # e.name = struct_name
            # # -------------------------------------------------------------------
            U32 = BASE_TYPES[clang.TypeKind.UINT]
            entry = sym_tbl.insert_entry('data', U32, clang.CursorKind.FIELD_DECL, None)
            entry.is_bpf_ctx = True
            entry = sym_tbl.insert_entry('data_end', U32, clang.CursorKind.FIELD_DECL, None)
            entry.is_bpf_ctx = True
            entry = sym_tbl.insert_entry('len', U32, clang.CursorKind.FIELD_DECL, None)
            entry.is_bpf_ctx = False
            # Just creat a record object for the sk_skb context
            fields = [StateObject.build('data', U32),
                    StateObject.build('data_end', U32),
                    StateObject.build('len', U32)]
            rec = Record('__sk_skb', fields)

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
        verdict_code = (self._pull_packet_data() +
                self._load_connection_state() + verdict_code)
        verdict_code = indent(verdict_code, 1)

        return '\n'.join(info.prog._parser_prog([per_conn] +
            [''] + [parser_code]) + [''] +
            info.prog._verdict_prog([verdict_code]))

    def send(self, buf, write_size, info, failure_return, ret=True, do_copy=True):
        if not do_copy:
            raise Exception('The sk_skb adjust size would not adjust tail but the head of the packet and this makes issues when the send buffer is already on the packet')
        super().send(buf, write_size, info, failure_return, ret, do_copy)

    def get_pkt_size(self):
        skb      = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        skb.name = self.ctx
        skb.type = self.ctx_type

        length      = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        length.name = 'len'
        length.type = BASE_TYPES[clang.TypeKind.UINT]
        length.owner.append(skb)
        return length

    def adjust_pkt(self, final_size, info):
        adjust_pkt   = Call(None)
        adjust_pkt.name = '__adjust_skb_size'
        adjust_pkt.args = [self.get_ctx_ref(), final_size]
        insts = [adjust_pkt]
        return insts, []

    def get_drop(self):
        return 'SK_DROP'

    def get_pass(self):
        return 'SK_PASS'

    def get_send(self):
        # raise Exception('not implemented')
        return f'return bpf_sk_redirect_map(skb, &sock_map, sock_ctx->sock_map_index, 0);'
