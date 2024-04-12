import template
from bpf import BPF_PROG
from data_structure import BASE_TYPES, Record, StateObject
from my_type import MyType
from instruction import *
from helpers.instruction_helper import *
from code_gen import gen_code
from internal_types import FLOW_ID_TYPE, FLOW_ID_PTR


class SK_SKB_PROG(BPF_PROG):
    def __init__(self):
        super().__init__()
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
        self.ctx_type = MyType.make_pointer(MyType.make_simple('struct __sk_buff', clang.TypeKind.RECORD))

    def set_bpf_context_struct_sym_tbl(self, sym_tbl):
        struct_name = '__sk_buff'
        fields = [StateObject.build('data', UINT),
                StateObject.build('data_end', UINT),
                StateObject.build('len', UINT),
                StateObject.build('sk', U64),]
        rec = Record(struct_name, fields)
        rec.update_symbol_table(sym_tbl)

        scope_key = f'class_struct {struct_name}'
        scope = sym_tbl.scope_mapping[scope_key]

        is_bpf_ctx = ['data', 'data_end']
        for field in is_bpf_ctx:
            entry = scope.lookup(field)
            assert entry is not None
            entry.is_bpf_ctx = True

    def set_code(self, code):
        self.verdict_code = code

    def _per_connection_state(self, info):
        fields = []
        for sym in info.sym_tbl.sk_state_scope.symbols.values():
            # TODO: probably I want to have another highlevel scope just for the type definitions
            if sym.kind in (clang.CursorKind.CLASS_DECL, clang.CursorKind.TYPEDEF_DECL):
                continue
            fields.append(StateObject.build(sym.name, sym.type))
        return ([
                '/* Put state of each socket in this struct (This will be used in sockops.h as',
                ' * part of per socket metadata) */',
                generate_struct_with_fields('connection_state', fields),
                '#include "sockops.h"',
                ])


    def _load_connection_state(self):
        return ''
        # return '''struct sock_context *sock_ctx;

# if (skb->sk == NULL) {
  # bpf_printk("The socket reference is NULL");
  # return SK_DROP;
# }
# sock_ctx = bpf_sk_storage_get(&sock_ctx_map, skb->sk, NULL, 0);
# if (!sock_ctx) {
  # bpf_printk("Failed to get socket context!");
  # return SK_DROP;
# }
# '''

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
        per_conn = info.prog._per_connection_state(info)
        parser_code, _ = gen_code(self.parser_code, info)
        parser_code = indent(parser_code, 1)
        verdict_code, _ = gen_code(self.verdict_code, info)
        verdict_code = (self._pull_packet_data() +
                self._load_connection_state() + verdict_code)
        verdict_code = indent(verdict_code, 1)

        tmp = (per_conn +
                [''] +
                info.prog._parser_prog([parser_code]) +
                [''] +
                info.prog._verdict_prog([verdict_code]))
        return '\n'.join(tmp)

    def send(self, buf, write_size, info, failure_return, ret=True, do_copy=True):
        if not do_copy:
            raise Exception('The sk_skb adjust size would not adjust tail but the head of the packet and this makes issues when the send buffer is already on the packet')
        return super().send(buf, write_size, info, failure_return, ret,
                do_copy)

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
        adjust_pkt.set_modified(InstructionColor.KNOWN_FUNC_IMPL)
        insts = [adjust_pkt]
        return insts, []

    def get_drop(self):
        return 'SK_DROP'

    def get_pass(self):
        return 'SK_PASS'

    def get_send(self, info):
        insts = []
        decl = []

        tmp_insts, tmp_decl, key = template.skskb_get_flow_id(None, info)
        insts.extend(tmp_insts)
        decl.extend(tmp_decl)

        map_ref_addr = UnaryOp.build('&', Literal(SOCK_MAP_NAME, CODE_LITERAL))
        map_ref_addr.set_modified()

        name = 'bpf_sk_redirect_hash'
        call_redir = Call(None)
        call_redir.name = name
        call_redir.args = [self.get_ctx_ref(), map_ref_addr, key, ZERO]
        call_redir.set_modified(InstructionColor.KNOWN_FUNC_IMPL)
        insts.append(call_redir)

        return insts, decl
