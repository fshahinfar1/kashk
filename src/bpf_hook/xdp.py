from bpf import BPF_PROG
from data_structure import (MyType, BASE_TYPES, XDP_HELPER_HEADER, Record,
        StateObject)
from instruction import *
from helpers.instruction_helper import *
from code_gen import gen_code
from . import cast_data

class XDP_PROG(BPF_PROG):

    def __init__(self):
        super().__init__()
        self.ctx = 'xdp'
        self.ctx_type = MyType.make_pointer(MyType.make_simple('struct xdp_md', clang.TypeKind.RECORD))
        self.declarations.extend([
                Literal('#define MAX_PACKET_SIZE 1472', CODE_LITERAL),
                Literal('#define DATA_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))', CODE_LITERAL),
            ])
        self.headers.extend([
            '#include <linux/in.h>',
            '#include <linux/if_ether.h>',
            '#include <linux/ip.h>',
            '#include <linux/udp.h>',
            ])

    def set_bpf_context_struct_sym_tbl(self, sym_tbl):
        """
        This adds the definition of the BPF context to the symbol table
        """
        T = self.ctx_type.under_type
        scope_key = f'class_{T.spelling}'
        entry = sym_tbl.global_scope.insert_entry(scope_key, T, clang.CursorKind.CLASS_DECL, None)
        entry.is_bpf_ctx = False
        with sym_tbl.new_scope() as scope:
            sym_tbl.scope_mapping[scope_key] = scope
            U32 = BASE_TYPES[clang.TypeKind.UINT]
            entry = sym_tbl.insert_entry('data', U32, clang.CursorKind.FIELD_DECL, None)
            entry.is_bpf_ctx = True
            entry = sym_tbl.insert_entry('data_end', U32, clang.CursorKind.FIELD_DECL, None)
            entry.is_bpf_ctx = True
            # Just creat a record object for the sk_skb context
            fields = [StateObject.build('data', U32),
                    StateObject.build('data_end', U32),]
            rec = Record('xdp_md', fields)

    def set_code(self, code):
        self.main_code = code

    def gen_code(self, info):
        check_traffic = f'''
{{
  void *data = (void *)(unsigned long long)xdp->data;
  void *data_end = (void *)(unsigned long long)xdp->data_end;
  struct ethhdr *eth = data;
  struct iphdr  *ip  = (void *)(eth + 1);
  struct udphdr *udp = (void *)(ip  + 1);
  if ((void *)(udp + 1) > data_end) return XDP_PASS;
  if (udp->dest != bpf_htons({self.server_config[1]})) return XDP_PASS;
}}
'''
        check_traffic = indent(check_traffic, 1)
        code,_ = gen_code(self.main_code, info)
        code = indent(code, 1)

        text = f'''
SEC("xdp")
int xdp_prog(struct xdp_md *xdp)
{{
{check_traffic}
{code}
}}
'''
        return text

    def get_pkt_buf(self):
        xdp = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        xdp.name = self.ctx
        xdp.type = self.ctx_type
        xdp.set_modified()

        ref = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        ref.name = 'data'
        ref.type = BASE_TYPES[clang.TypeKind.UINT]
        ref.owner.append(xdp)
        ref.set_modified()

        cast1 = Cast.build(ref, U64)
        data_off = Literal('DATA_OFFSET', clang.CursorKind.INTEGER_LITERAL)
        add_off = BinOp.build(cast1, '+', data_off)
        cast2 = Cast.build(add_off,  VOID_PTR)
        cast1.set_modified()
        cast2.set_modified()
        return cast2

    def get_pkt_end(self):
        xdp = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        xdp.name = 'xdp'
        xdp.type = self.ctx_type
        xdp.set_modified()

        ref = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        ref.name = 'data_end'
        ref.type = BASE_TYPES[clang.TypeKind.UINT]
        ref.owner.append(xdp)
        ref.set_modified()
        return cast_data(ref)

    def get_pkt_size(self):
        end = self.get_pkt_end()
        beg = self.get_pkt_buf()

        delta = BinOp.build(end, '-', beg)
        delta.set_modified()
        size  = Cast.build(delta,  BASE_TYPES[clang.TypeKind.USHORT])
        size.set_modified()
        return size

    def adjust_pkt(self, req_size, info):
        # NOTE: in xdp we do not want to modify the eth/ip/udp headers. We are
        # targeting network APPLICATIONS. They do not operate on transport
        # header.
        # header_size = Literal('DATA_OFFSET', clang.CursorKind.INTEGER_LITERAL)
        # final_size = BinOp.build(req_size, '+', header_size)
        # NOTE 2: since we have updated the get_pkt_size to not include the
        # header size we do not need to update here! (got a bit complex :) )

        decl = []

        delta_ref = decl_new_var(INT, info, decl)
        compute_size = BinOp.build(req_size, '-', self.get_pkt_size())
        compute_size.set_modified(InstructionColor.EXTRA_ALU_OP)
        delta_assign = BinOp.build(delta_ref, '=', compute_size)
        delta_assign.set_modified()

        adjust_pkt      = Call(None)
        adjust_pkt.name = 'bpf_xdp_adjust_tail'
        adjust_pkt.args = [self.get_ctx_ref(), delta_ref]
        adjust_pkt.set_modified(InstructionColor.KNOWN_FUNC_IMPL)
        insts = [delta_assign, adjust_pkt]
        return insts, decl

    def get_drop(self):
        return 'XDP_DROP'

    def get_pass(self):
        return 'XDP_PASS'

    def get_send(self):
        return Literal('XDP_TX', clang.CursorKind.INTEGER_LITERAL)

    def before_send(self):
        if XDP_HELPER_HEADER not in self.headers:
            self.headers.append(XDP_HELPER_HEADER)
        xdp = Ref.build(self.ctx, self.ctx_type)
        call = Call(None)
        call.name = '__prepare_headers_before_send'
        call.args.append(xdp)
        call.set_modified(InstructionColor.KNOWN_FUNC_IMPL)
        return [call,]

    def before_pass(self):
        if XDP_HELPER_HEADER not in self.headers:
            self.headers.append(XDP_HELPER_HEADER)
        xdp = Ref.build(self.ctx, self.ctx_type)
        call = Call(None)
        call.name = '__prepare_headers_before_pass'
        call.args.append(xdp)
        call.set_modified(InstructionColor.KNOWN_FUNC_IMPL)
        return [call,]
