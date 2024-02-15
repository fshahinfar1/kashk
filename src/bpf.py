import clang.cindex as clang
from utility import generate_struct_with_fields, indent, get_tmp_var_name
from data_structure import MyType, BASE_TYPES
from instruction import *
from helpers.instruction_helper import *
import template

from bpf_hook import cast_data
from elements.likelihood import Likelihood


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
                '/* vim: set et ts=2 sw=2: */',
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
        return cast_data(ref)


    def get_pkt_end(self):
        xdp = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        xdp.name = self.ctx
        xdp.type = self.ctx_type

        ref = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        ref.name = 'data_end'
        ref.type = BASE_TYPES[clang.TypeKind.UINT]
        ref.owner.append(xdp)
        return cast_data(ref)

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

        inst, decl = self.adjust_pkt(write_size, info)
        inst = decl + inst
        if do_copy:
            if memcpy == 'memcpy':
                off          = BinOp.build(self.get_pkt_buf(), '+', write_size)
                cond         = BinOp.build(off, '>', self.get_pkt_end())
                check        = ControlFlowInst.build_if_inst(cond)
                ret_inst     = failure_return
                check.body.add_inst(ret_inst)
                check.set_modified(InstructionColor.CHECK)
                check.likelihood = Likelihood.Unlikely

                copy         = Call(None)
                copy.name    = memcpy
                args         = [self.get_pkt_buf(), buf, write_size]
                copy.args = args
                copy.set_modified(InstructionColor.MEM_COPY)
                inst.extend([check, copy])
            else:
                # variable copy
                dst = self.get_pkt_buf()
                dst.type = CHAR_PTR
                ret_value = None
                if failure_return.body.has_children():
                    ret_value = failure_return.body.children[0]
                loop, decl, tmp_ret = template.variable_memcpy(dst, buf,
                        write_size, 1470, info, ret_value)
                inst.extend(decl)
                inst.append(loop)

        # Do anything that is needed before sending
        before_send_insts = self.before_send()
        inst.extend(before_send_insts)

        if ret is True:
            ret_val  = self.get_send()
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

    def before_pass(self):
        return []
