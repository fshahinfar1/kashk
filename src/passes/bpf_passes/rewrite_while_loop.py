import clang.cindex as clang
from passes.code_pass import Pass
from data_structure import *
from instruction import *
import template
from helpers.instruction_helper import UINT
from utility import find_elems_of_kind
from elements.after import After
from passes.update_original_ref import set_original_ref


class RewriteWhileLoop(Pass):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _get_upper_bound_for(seslf, inst):
        upper_bound_int = inst.repeat
        if upper_bound_int is None:
            upper_bound_int = 32
            error('Missing the upper bound for a while loop')
        upper_bound = Literal(str(upper_bound_int),
                clang.CursorKind.INTEGER_LITERAL)
        return upper_bound

    def _handle_while(self, inst, more):
        upper_bound = self._get_upper_bound_for(inst)
        tmp_insts, tmp_decl, loop_var = template.new_bounded_loop(upper_bound,
                upper_bound, self.info, self.current_function,
                loop_var_type=UINT, fail_check=True)
        loop = tmp_insts[0]
        self.declare_at_top_of_func.extend(tmp_decl)
        set_original_ref(tmp_insts, self.info, inst.original)

        while_cond = inst.cond.children[0]
        _tmp = Parenthesis.build(while_cond)
        break_cond = UnaryOp.build('!', _tmp)
        check_break = ControlFlowInst.build_if_inst(break_cond)
        break_inst = Instruction()
        break_inst.kind = clang.CursorKind.BREAK_STMT
        check_break.body.add_inst(break_inst)
        set_original_ref(check_break, self.info, while_cond.original)
        loop.body.add_inst(check_break)

        while_body = inst.body
        loop.body.extend_inst(while_body.children)
        blk = self.cb_ref.get(BODY)
        after = After(tmp_insts[1:])
        blk.append(after)
        loop.body.original = while_body.original
        return loop

    def _handle_do_while(self, inst, more):
        upper_bound = self._get_upper_bound_for(inst)
        tmp_insts, tmp_decl, loop_var = template.new_bounded_loop(upper_bound,
                upper_bound, self.info, self.current_function,
                loop_var_type=UINT, fail_check=True)
        loop = tmp_insts[0]
        self.declare_at_top_of_func.extend(tmp_decl)
        set_original_ref(tmp_insts, self.info, inst.original)

        while_cond = inst.cond.children[0]
        _tmp = Parenthesis.build(while_cond)
        break_cond = UnaryOp.build('!', _tmp)
        check_break = ControlFlowInst.build_if_inst(break_cond)
        break_inst = Instruction()
        break_inst.kind = clang.CursorKind.BREAK_STMT
        check_break.body.add_inst(break_inst)
        set_original_ref(check_break, self.info, while_cond.original)

        while_body = inst.body
        _tmp = find_elems_of_kind(while_body, clang.CursorKind.CONTINUE_STMT)
        assert len(_tmp) == 0, 'I do not expect continue statement in this loop! there will be a bug otherwise'
        loop.body.extend_inst(while_body.children)

        # Add the break condition check to the end of the body of the loop
        # TODO: what happens if the loop has a continue statements?
        tmp_list = find_elems_of_kind(while_body.children, clang.CursorKind.CONTINUE_STMT)
        assert len(tmp_list) == 0, 'TODO: if there are continue statements inside do-while I need to check the loop condition before continue! Not implemented yet!'

        loop.body.add_inst(check_break)
        blk = self.cb_ref.get(BODY)
        after = After(tmp_insts[1:])
        blk.append(after)
        loop.body.original = while_body.original
        return loop

    def process_current_inst(self, inst, more):
        if inst.kind == clang.CursorKind.WHILE_STMT:
            return self._handle_while(inst, more)
        elif inst.kind == clang.CursorKind.DO_STMT:
            return self._handle_do_while(inst, more)
        else:
            return inst


def rewrite_while_loop(bpf, info, more):
    obj = RewriteWhileLoop.do(bpf, info, more)
    res = obj.result
    _tmp = Function.directory.values()
    functions = filter(lambda f: f.is_used_in_bpf_code, _tmp)
    for func in functions:
        obj = RewriteWhileLoop.do(func.body, info, more=None, func=func)
        func.body = obj.result
    return res
