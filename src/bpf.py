import clang.cindex as clang
from utility import generate_struct_with_fields, indent, get_tmp_var_name
from data_structure import MyType, BASE_TYPES, XDP_HELPER_HEADER
from instruction import *
from log import debug
from bpf_code_gen import gen_code

from helpers.instruction_helper import CHAR_PTR
import template


MODULE_TAG = '[BPF Prog]'


def _use_memcpy(info):
    func = Function.directory['bpf_memcpy']
    if not func.is_used_in_bpf_code:
        func.is_used_in_bpf_code = True
        info.prog.declarations.insert(0, func)
        prerequisite = Literal('''struct bpf_memcpy_ctx {
  unsigned short i;
  char *dest;
  char *src;
  unsigned short n;
  void *end_dest;
  void *end_src;
};

static long
bpf_memcpy_loop(unsigned int index, void *arg)
{
  struct bpf_memcpy_ctx *ll = arg;
  if ((void *)(ll->dest + ll->i + 1) > ll->end_dest)
    return 1;
  if ((void *)(ll->src  + ll->i + 1) > ll->end_src)
    return 1;
  ll->dest[ll->i] = ll->src[ll->i];
  if (ll->i >= ll->n - 1) {
    return 1;
  }
  ll->i++;
  return 0;
}''', CODE_LITERAL)
        info.prog.add_declaration(prerequisite)


class BPF_PROG:
    def __init__(self):
        self.declarations = [
                Literal('''#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif

#ifndef memmove
#define memmove(d, s, len) __builtin_memmove(d, s, len)
#endif

#ifndef memset
#define memset(d, c, len) __builtin_memset(d, c, len)
#endif
''', CODE_LITERAL),
                Literal('typedef char bool;', CODE_LITERAL),
                Literal('#define PKT_OFFSET_MASK 0xfff', CODE_LITERAL),
                #Literal('''#ifndef bpf_loop
#static long (*bpf_loop)(__u32 nr_loops, void *callback_fn, void *callback_ctx, __u64 flags) = (void *) 181;
##endif
##ifndef bpf_strncmp
#static long (*bpf_strncmp)(const char *s1, __u32 s1_sz, const char *s2) = (void *) 182;
##endif''', CODE_LITERAL),
                ]
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
        self.ctx_type = MyType()
        self.server_config = ('127.0.0.1', '8080')
        self.index_mask = Literal('PKT_OFFSET_MASK',
                clang.CursorKind.MACRO_INSTANTIATION)
        self.max_loop_iteration = Literal('256',
                clang.CursorKind.INTEGER_LITERAL)

    def get_ctx_ref(self):
        return Ref.build(self.ctx, self.ctx_type)

    def add_declaration(self, text):
        self.declarations.append(text)

    def set_bpf_context_struct_sym_tbl(self, sym_tbl):
        raise Exception('Not implemented!')

    def gen_code(self, info):
        raise Exception('Not implemented!')

    def set_code(self, code):
        raise Exception('Not implemented!')

    def get_pkt_buf(self):
        xdp = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        xdp.name = self.ctx
        xdp.type = self.ctx_type

        ref = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        ref.name = 'data'
        ref.type = BASE_TYPES[clang.TypeKind.UINT]
        ref.owner.append(xdp)

        cast1 = Cast()
        cast1.castee.add_inst(add_off)
        cast1.type = BASE_TYPES[clang.TypeKind.ULONGLONG]
        cast2 = Cast()
        cast2.castee.add_inst(cast1)
        cast2.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
        return cast2


    def get_pkt_end(self):
        raise Exception('Not implemented!')

    def get_pkt_size(self):
        raise Exception('Not implemented!')

    def add_args_to_scope(self, scope):
        """
        This function adds the instance of the BPF context to the scope.
        """
        T = self.ctx_type
        xdp_entry = scope.insert_entry(self.ctx, T, clang.CursorKind.PARM_DECL, None)
        xdp_entry.is_bpf_ctx = False
        entry = xdp_entry.fields.insert_entry('data',
                BASE_TYPES[clang.TypeKind.UINT],
                clang.CursorKind.MEMBER_REF_EXPR, None)
        entry.is_bpf_ctx = True
        entry = xdp_entry.fields.insert_entry('data_end',
                BASE_TYPES[clang.TypeKind.UINT],
                clang.CursorKind.MEMBER_REF_EXPR, None)
        entry.is_bpf_ctx = True

    def send(self, buf, write_size, info, failure_return, ret=True, do_copy=True):
        #TODO: The arguments of this function are crazy ???
        is_size_integer = write_size.kind == clang.CursorKind.INTEGER_LITERAL
        if is_size_integer:
            memcpy = 'memcpy'
        else:
            memcpy = 'bpf_memcpy'
            # The BPF_MEMCPY with bpf_loop does not work very well for now.
            # I will use a simple for loop with an upper bound.
            # _use_memcpy(info)

        inst = self.adjust_pkt(write_size, info)
        if do_copy:
            if memcpy == 'memcpy':
                off          = BinOp.build(self.get_pkt_buf(), '+', write_size)
                cond         = BinOp.build(off, '>', self.get_pkt_end())
                check        = ControlFlowInst.build_if_inst(cond)
                ret_inst     = failure_return
                check.body.add_inst(ret_inst)

                copy         = Call(None)
                copy.name    = memcpy
                args         = [self.get_pkt_buf(), buf, write_size]
                copy.args = args
                inst.extend([check, copy])
            else:
                # variable copy
                dst = self.get_pkt_buf()
                dst.type = CHAR_PTR
                loop, decl = template.variable_memcpy(dst, buf, write_size,
                        1470, info)
                inst.extend(decl)
                inst.append(loop)

        if ret is True:
            ret_val  = Literal(self.get_send(), clang.CursorKind.INTEGER_LITERAL)
            ret_inst = Return.build([ret_val,])
            inst.append(ret_inst)
        return inst

    def adjust_pkt(self, final_size, info):
        raise Exception('Not implemented!');

    def get_drop(self):
        raise Exception('Not implemented!')

    def get_pass(self):
        raise Exception('Not implemented!')

    def get_send(self):
        raise Exception('Not implemented!')

    def get_ctx_ref(self):
        ref = Ref(None)
        ref.name = self.ctx
        ref.kind = clang.CursorKind.DECL_REF_EXPR
        ref.type = self.ctx_type
        return ref

    def before_send(self):
        return []


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

        ref = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        ref.name = 'data'
        ref.type = BASE_TYPES[clang.TypeKind.UINT]
        ref.owner.append(xdp)

        cast1 = Cast()
        cast1.castee.add_inst(ref)
        cast1.type = BASE_TYPES[clang.TypeKind.ULONGLONG]

        data_off = Literal('DATA_OFFSET', clang.CursorKind.INTEGER_LITERAL)
        add_off = BinOp.build(cast1, '+', data_off)

        cast2 = Cast()
        cast2.castee.add_inst(add_off)
        cast2.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
        return cast2

    def get_pkt_end(self):
        xdp = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        xdp.name = 'xdp'
        xdp.type = self.ctx_type

        ref = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        ref.name = 'data_end'
        ref.type = BASE_TYPES[clang.TypeKind.UINT]
        ref.owner.append(xdp)

        cast1 = Cast()
        cast1.castee.add_inst(ref)
        cast1.type = BASE_TYPES[clang.TypeKind.ULONGLONG]
        cast2 = Cast()
        cast2.castee.add_inst(cast1)
        cast2.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
        return cast2

    def get_pkt_size(self):
        end = self.get_pkt_end()
        beg = self.get_pkt_buf()

        delta = BinOp.build(end, '-', beg)
        size  = Cast.build(delta,  BASE_TYPES[clang.TypeKind.USHORT])
        return size

    def adjust_pkt(self, req_size, info):
        # NOTE: in xdp we do not want to modify the eth/ip/udp headers. We are
        # targeting network APPLICATIONS. They do not operate on transport
        # header.
        # header_size = Literal('DATA_OFFSET', clang.CursorKind.INTEGER_LITERAL)
        # final_size = BinOp.build(req_size, '+', header_size)
        # NOTE 2: since we have updated the get_pkt_size to not include the
        # header size we do not need to update here! (got a bit complex :) )

        tmp_name = get_tmp_var_name()
        decl         = VarDecl.build(tmp_name, BASE_TYPES[clang.TypeKind.INT])
        delta_ref    = decl.get_ref()
        compute_size = BinOp.build(req_size, '-', self.get_pkt_size())
        delta_assign = BinOp.build(delta_ref, '=', compute_size)
        decl.update_symbol_table(info.sym_tbl)

        adjust_pkt   = Call(None)
        adjust_pkt.name = 'bpf_xdp_adjust_tail'
        adjust_pkt.args = [self.get_ctx_ref(), delta_ref]
        insts = [decl, delta_assign, adjust_pkt]
        return insts

    def get_drop(self):
        return 'XDP_DROP'

    def get_pass(self):
        return 'XDP_PASS'

    def get_send(self):
        return 'XDP_TX'

    def before_send(self):
        if XDP_HELPER_HEADER not in self.headers:
            self.headers.append(XDP_HELPER_HEADER)
        xdp = Ref.build(self.ctx, self.ctx_type)
        call = Call(None)
        call.name = '__prepare_headers_before_send'
        call.args.append(xdp)
        return [call,]


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
        sym_tbl.insert_entry(scope_key, T, clang.CursorKind.CLASS_DECL, None)
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
        return insts

    def get_drop(self):
        return 'SK_DROP'

    def get_pass(self):
        return 'SK_PASS'

    def get_send(self):
        # raise Exception('not implemented')
        return f'return bpf_sk_redirect_map(skb, &sock_map, sock_ctx->sock_map_index, 0);'
