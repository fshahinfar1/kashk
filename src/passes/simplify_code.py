import clang.cindex as clang

from log import error, debug, report
from data_structure import *
from instruction import *
from my_type import MyType
from utility import get_tmp_var_name
from passes.clone import clone_pass
from passes.code_pass import Pass
from helpers.instruction_helper import decl_new_var
from passes.update_original_ref import set_original_ref


MODULE_TAG = '[Linear Code Pass]'


def _make_sure_void_func_return(func, info):
    last_inst = func.body.children[-1]
    if last_inst.kind == clang.CursorKind.RETURN_STMT:
        # The function end with a return
        return
    ret_inst = Return()
    func.body.add_inst(ret_inst)


def _assign_block_to(blk, ref):
    assert len(blk.children)
    assign = BinOp.build(ref, '=', blk.children[0])
    return assign


def inst_type(inst):
    if inst.kind in (clang.CursorKind.DECL_REF_EXPR,
            clang.CursorKind.MEMBER_REF_EXPR, clang.CursorKind.VAR_DECL,
            clang.CursorKind.CSTYLE_CAST_EXPR):
        return inst.type
    elif inst.kind in (clang.CursorKind.PAREN_EXPR,):
        return inst_type(inst.body.children[0])
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        return inst.return_type
    elif inst.kind == clang.CursorKind.INTEGER_LITERAL:
        return BASE_TYPES[clang.TypeKind.INT]
    else:
        error(MODULE_TAG, 'ignoring some cases:', inst,inst.kind)
    return MyType.make_simple('<Unknown>', clang.TypeKind.RECORD)


class SimplifyCode(Pass):
    def __init__(self, info):
        super().__init__(info)

    def _handle_conditional_operator(self, inst):
        blk = self.cb_ref.get(BODY)

        # TODO: does type of body and other body match?
        # TODO: is it possible that body do not have a child?
        T = inst_type(inst.body.children[0])
        tmp_var = VarDecl.build(get_tmp_var_name(), T)
        tmp_ref = tmp_var.get_ref()
        blk.append(tmp_var)
        tmp_var.update_symbol_table(self.info.sym_tbl)

        assert len(inst.cond.children) == 1
        cond = inst.cond.children[0]
        if_stmt = ControlFlowInst.build_if_inst(cond)
        if inst.body.has_children():
            assign = _assign_block_to(inst.body, tmp_ref)
        else:
            assign = _assign_block_to(if_stmt.cond, tmp_ref)
        if_stmt.body.add_inst(assign)

        if inst.other_body.has_children():
            assign = _assign_block_to(inst.other_body, tmp_ref)
        else:
            assign = _assign_block_to(if_stmt.cond, tmp_ref)
        if_stmt.other_body.add_inst(assign)
        blk.append(if_stmt)
        set_original_ref(if_stmt, self.info, inst.original)
        return tmp_ref

    def _separate_var_decl_and_init(self, inst, more):
        blk = self.cb_ref.get(BODY)
        assert blk is not None
        clone = clone_pass(inst)
        rhs = clone.init.children[0]
        # clear the children
        clone.init.children.clear()
        ref = inst.get_ref()
        bin_op = BinOp.build(ref, '=', rhs)
        # If the declartion was ignored, also ignore the initialization
        bin_op.ignore = clone.ignore
        set_original_ref(bin_op, self.info, inst.original)
        blk.append(clone)
        if more.ctx != BODY:
            blk.append(bin_op)
        return bin_op

    def _move_function_out(self, inst):
        info = self.info
        return_type = None
        if inst.is_func_ptr:
            ref = inst.owner[0]
            ref_type = ref.type
            while ref_type.kind == clang.TypeKind.TYPEDEF:
                ref_type = ref_type.under_type
            assert ref_type.kind == clang.TypeKind.POINTER
            under_type = ref_type.under_type
            assert under_type.kind == clang.TypeKind.FUNCTIONPROTO
            return_type = under_type.func_proto_obj.ret
        else:
            func = inst.get_function_def()
            if not func:
                debug(MODULE_TAG, 'can not move a function that do not know the definition: ', inst.name)
                return inst
            return_type = func.return_type

        assert return_type is not None

        blk = self.cb_ref.get(BODY)
        assert blk is not None

        if return_type.spelling != 'void':
            tmp_var_name = get_tmp_var_name()
            # Declare tmp
            T = return_type
            assert isinstance(T, MyType)
            tmp_decl = VarDecl.build(tmp_var_name, T)
            blk.append(tmp_decl)
            tmp_decl.update_symbol_table(info.sym_tbl)

            # Assign function return value to tmp
            tmp_ref = tmp_decl.get_ref()
            cloned_inst = clone_pass(inst)
            bin_op = BinOp.build(tmp_ref, '=', cloned_inst)
            blk.append(bin_op)

            tmp_decl.ignore = cloned_inst.ignore
            tmp_decl.original = cloned_inst.original
            bin_op.ignore = cloned_inst.ignore
            bin_op.original = cloned_inst.original

            # Use a variable instead of function call
            return tmp_ref.clone([])
        raise Exception('Not implemented yet!')

    def _move_index_out(self, inst):
        assert isinstance(inst, ArrayAccess)
        # TODO: can we decide type for all the cases?
        index = inst.index.children[0]
        T = index.type
        ref = decl_new_var(T, self.info, self.declare_at_top_of_func)
        assign = BinOp.build(ref, '=', index)

        ref.original = index.original
        assign.original = index.original

        blk = self.cb_ref.get(BODY)
        blk.append(assign)

        new_inst = clone_pass(inst)
        new_inst.index.children.clear()
        new_inst.index.children.append(ref)
        return new_inst

    def process_current_inst(self, inst, more):
        ctx = more.ctx
        if inst.kind == clang.CursorKind.CALL_EXPR:
            if ctx in (ARG, LHS):
                if inst.is_operator:
                    # Let's not mess up with operators
                    return inst
                return self._move_function_out(inst)
            elif ctx == RHS:
                parent = self.get_valid_parent()
                if (parent is None
                        or parent.kind != clang.CursorKind.BINARY_OPERATOR
                        or parent.op == '='):
                    return inst
                return self._move_function_out(inst)
        elif inst.kind == clang.CursorKind.VAR_DECL:
            if inst.has_children() and not inst.type.is_array():
                return self._separate_var_decl_and_init(inst, more)
        elif inst.kind == clang.CursorKind.CONDITIONAL_OPERATOR:
            return self._handle_conditional_operator(inst)
        elif inst.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
            # TODO: we should also move on the owner of the references
            index = inst.index.children[0]
            if isinstance(index, Literal):
                return inst
            if isinstance(index, Ref):
                # if the reference is on a map we should move it out
                sym, scope = self.info.sym_tbl.lookup2(index.name)
                if sym is None:
                    debug('Did not found the symbol for', sym, tag=MODULE_TAG)
                    return inst
                is_global = scope == self.info.sym_tbl.global_scope
                is_shared = scope == self.info.sym_tbl.shared_scope
                if not is_shared and not is_global:
                    # It is fine
                    return inst
            # Move the indexing calculation out
            return self._move_index_out(inst)
        return inst


def simplify_code_structure(inst, info, more):
    """
    The following transformations are performed in this pass

    1. Move function calls out of argument places. It include if-statement
    condition, other function arguments, etc. This is done because we need to
    add some checks after or before some functions, they should be in a block
    of code and not in an argument.

    2. Seperate value declaration and initialization to two different
    instructions (declaration and assignment). [I have forgot why I needed this]

    3. Convert conditional operations (ternary operations) to if else
    instructions. This is needed for the similar reason as case 1. If some
    operation in each path of this operation need a check then we would like to
    add it in a block of code. The ternary operation does no allow this.

    4. Make sure all void functions terminate with a return statement. It is
    valid for a void function to not have return instruction, but we are using
    return instruction as a sign of end of the function in future passes.
    """
    res = SimplifyCode.do(inst, info, more).result
    # Make sure all the void functions are terminated with Return instructions
    # Other functions must return something so the compiler should complain.
    for func in Function.directory.values():
        if not func.is_used_in_bpf_code:
            continue
        tmp = SimplifyCode.do(func.body, info, func=func).result
        func.body = tmp
        if not func.is_empty() and func.return_type.spelling == 'void':
            _make_sure_void_func_return(func, info)
    return res
