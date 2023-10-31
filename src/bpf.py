import clang.cindex as clang
from utility import generate_struct_with_fields, indent
from data_structure import MyType, BASE_TYPES
from instruction import *
from log import debug
from bpf_code_gen import gen_code


MODULE_TAG = '[BPF Prog]'


class BPF_PROG:
    def __init__(self):
        self.declarations = [Literal(' #define PKT_OFFSET_MASK 0xfff;', CODE_LITERAL),]
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
        self.index_mask = Literal('PKT_OFFSET_MASK', clang.CursorKind.MACRO_INSTANTIATION)

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

    def get_pkt_end(self):
        raise Exception('Not implemented!')

    def get_pkt_size(self):
        raise Exception('Not implemented!')

    def add_args_to_scope(self, scope):
        raise Exception('Not implemented!')

    def send(self, buf, write_size, info, ret=True, failure='XDP_DROP', do_copy=True):
        raise Exception('Not implemented!')

    def adjust_pkt(self, final_size):
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


class XDP_PROG(BPF_PROG):

    def __init__(self):
        super().__init__()
        self.ctx = 'xdp'
        self.ctx_type = MyType.make_pointer(MyType.make_simple('struct xdp_md', clang.TypeKind.RECORD))
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
        struct_name = 'xdp'
        T = self.ctx_type.under_type
        scope_key = f'class_{T.spelling}'
        entry = sym_tbl.global_scope.insert_entry(struct_name, T, clang.CursorKind.CLASS_DECL, None)
        entry.is_bpf_ctx = True
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
        xdp.name = 'xdp'
        xdp.type = self.ctx_type

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
        cast1.cast_type = BASE_TYPES[clang.TypeKind.ULONGLONG]
        cast2 = Cast()
        cast2.castee.add_inst(cast1)
        cast2.cast_type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
        return cast2

    def get_pkt_size(self):
        xdp      = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        xdp.name = 'xdp'
        xdp.type = self.ctx_type

        data      = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        data.name = 'data'
        data.type = BASE_TYPES[clang.TypeKind.UINT]
        data.owner.append(xdp)

        data_end      = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        data_end.name = 'data_end'
        data_end.type = BASE_TYPES[clang.TypeKind.UINT]
        data_end.owner.append(xdp)

        end = Cast.build(data_end, BASE_TYPES[clang.TypeKind.ULONGLONG])
        beg = Cast.build(data,     BASE_TYPES[clang.TypeKind.ULONGLONG])

        delta = BinOp.build_op(end, '-', beg)
        size  = Cast.build(delta,  BASE_TYPES[clang.TypeKind.USHORT])
        return size

    def add_args_to_scope(self, scope):
        """
        This function adds the instance of the BPF context to the scope.
        """
        T = MyType.make_pointer(MyType.make_simple('xdp_md', clang.TypeKind.RECORD))
        xdp_entry = scope.insert_entry('xdp', T, clang.CursorKind.PARM_DECL, None)
        xdp_entry.is_bpf_ctx = True
        entry = xdp_entry.fields.insert_entry('data', BASE_TYPES[clang.TypeKind.UINT], clang.CursorKind.MEMBER_REF_EXPR, None)
        entry.is_bpf_ctx = True
        entry = xdp_entry.fields.insert_entry('data_end', BASE_TYPES[clang.TypeKind.UINT], clang.CursorKind.MEMBER_REF_EXPR, None)
        entry.is_bpf_ctx = True

    def send(self, buf, write_size, info, ret=True, failure='XDP_DROP', do_copy=True):
        #TODO: The arguments of this function are crayz ???
        is_size_integer = write_size.kind == clang.CursorKind.INTEGER_LITERAL
        if is_size_integer:
            memcpy = 'memcpy'
        else:
            # TODO: I need to check that BPF MEMCPY succeeds
            memcpy = 'bpf_memcpy'
            func = Function.directory[memcpy]
            if not func.is_used_in_bpf_code:
                func.is_used_in_bpf_code = True
                info.prog.declarations.insert(0, func)

        write_size,_ = gen_code([write_size], info, ARG)
        code = f'''
{{
  int delta = {write_size} - (unsigned short)((unsigned long long)xdp->data_end - (unsigned long long)xdp->data);
  bpf_xdp_adjust_tail(xdp, delta);
}}
if (((void *)(__u64)xdp->data + {write_size}) > (void *)(__u64)xdp->data_end) {{
    return {failure};
}}
'''

        if do_copy:
            if memcpy == 'memcpy':
                code += f'\n{memcpy}((void *)(unsigned long long)xdp->data, {buf}, {write_size});'
            else:
                code += f'\n{memcpy}((void *)(unsigned long long)xdp->data, {buf}, {write_size}, (void *)(unsigned long long)xdp->data_end, {buf} + {write_size});'
        if ret is True:
            code += '\nreturn XDP_TX;'
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

    def get_pkt_size(self):
        skb      = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        skb.name = self.ctx
        skb.type = self.ctx_type

        length      = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        length.name = 'len'
        length.type = BASE_TYPES[clang.TypeKind.UINT]
        length.owner.append(skb)

        # return Literal(f'skb->len', CODE_LITERAL)
        return length

    def add_args_to_scope(self, scope):
        T = self.ctx_type
        scope.insert_entry('skb', T, clang.CursorKind.PARM_DECL, None)

    def send(self, buf, write_size, info, ret=True, failure='SK_DROP', do_copy=True):
        is_size_integer = write_size.kind == clang.CursorKind.INTEGER_LITERAL
        if is_size_integer:
            memcpy = 'memcpy'
        else:
            # TODO: I need to check that BPF MEMCPY succeeds
            memcpy = 'bpf_memcpy'
            func = Function.directory[memcpy]
            if not func.is_used_in_bpf_code:
                debug(MODULE_TAG, 'Add bpf_memcpy to declarations')
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
