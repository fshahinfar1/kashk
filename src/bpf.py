import clang.cindex as clang
from utility import generate_struct_with_fields, indent, get_tmp_var_name
from data_structure import BASE_TYPES
from instruction import *
from my_type import MyType
from helpers.instruction_helper import *
import template

from bpf_hook import cast_data
from elements.likelihood import Likelihood


MODULE_TAG = '[BPF Prog]'


class BPF_PROG:
    def __init__(self):
        self.declarations = [
                Literal('typedef char bool;', CODE_LITERAL),
                Literal('#define PKT_OFFSET_MASK 0xfff', CODE_LITERAL),
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

    def send(self, buf, write_size, info, func, ret=True, do_copy=True):
        assert isinstance(func, (Function, type(None))), str(func)
        decl = []
        #TODO: The arguments of this function are crazy ???
        is_size_integer = write_size.kind == clang.CursorKind.INTEGER_LITERAL
        inst, tmp_decl = self.adjust_pkt(write_size, info)
        decl.extend(tmp_decl)
        if do_copy:
            # Get a reference to the packet payload in a variable
            pkt = self.get_pkt_buf()
            dst = decl_new_var(CHAR_PTR, info, inst, name=None)
            assign = BinOp.build(dst, '=', pkt)
            inst.append(assign)

            if is_size_integer:
                off          = BinOp.build(dst, '+', write_size)
                cond         = BinOp.build(off, '>', self.get_pkt_end())
                check        = ControlFlowInst.build_if_inst(cond)
                fail         = ToUserspace.from_func_obj(func)
                check.body.add_inst(fail)
                check.set_modified(InstructionColor.CHECK)
                check.likelihood = Likelihood.Unlikely

                copy = template.constant_mempcy(dst, buf, write_size)
                copy.set_modified(InstructionColor.MEM_COPY)
                inst.extend([check, copy])
            else:
                # variable copy
                tmp_insts, tmp_decl, tmp_ret = template.variable_memcpy(dst, buf,
                        write_size, 1470, info, func)
                decl.extend(tmp_decl)
                inst.extend(tmp_insts)

        # Do anything that is needed before sending
        before_send_insts = self.before_send()
        inst.extend(before_send_insts)

        if ret is True:
            tmp_inst, tmp_decl  = self.get_send(info)
            decl.extend(tmp_decl)
            inst.extend(tmp_inst[:-1])
            ret_val = tmp_inst[-1]
            ret_inst = Return.build([ret_val,])
            inst.append(ret_inst)
        return inst, decl

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
