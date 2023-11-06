from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug, report
from data_structure import *
from instruction import *
from utility import get_tmp_var_name
from helpers.instruction_helper import show_insts

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from passes.clone import clone_pass


MODULE_TAG = '[Linear Code Pass]'
cb_ref = CodeBlockRef()

# TODO: this is a hack, I should use a stack to associate a mapping for each
# scope. I am Lazy:) (issue is more time constraint than lazy)
func_ptr_mapping = {}

def _make_sure_void_func_return(func, info):
    last_inst = func.body.children[-1]
    if last_inst.kind == clang.CursorKind.RETURN_STMT:
        # The function end with a return
        return
    ret_inst = Return()
    func.body.add_inst(ret_inst)
    # report('Add return statement to the end of', func.name)

def _move_function_out(inst, info, more):
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

    blk = cb_ref.get(BODY)
    assert blk is not None

    if return_type.spelling != 'void':
        tmp_var_name = get_tmp_var_name()
        # Declare tmp
        T = return_type
        assert isinstance(T, MyType)
        tmp_decl = VarDecl(None)
        tmp_decl.name = tmp_var_name
        tmp_decl.type = T
        tmp_decl.state_obj = None
        blk.append(tmp_decl)

        # Update the symbol table
        info.sym_tbl.insert_entry(tmp_decl.name, T, tmp_decl.kind, None)

        # Assign function return value to tmp
        tmp_ref = Ref(None, kind=clang.CursorKind.DECL_REF_EXPR)
        tmp_ref.name = tmp_var_name
        tmp_ref.type = T
        bin_op = BinOp(None)
        bin_op.op = '='
        bin_op.lhs.add_inst(tmp_ref)
        cloned_inst = clone_pass(inst, info, PassObject())
        bin_op.rhs.add_inst(cloned_inst)
        blk.append(bin_op)

        tmp_decl.bpf_ignore = cloned_inst.bpf_ignore
        bin_op.bpf_ignore = cloned_inst.bpf_ignore

        # Use a variable instead of function call
        return tmp_ref.clone([])
    raise Exception('Not implemented yet!')


def _separate_var_decl_and_init(inst, info, more):
    blk = cb_ref.get(BODY)
    assert blk is not None
    clone = clone_pass(inst, info, PassObject())
    rhs = clone.init.children[0]
    # clear the children
    clone.init.children = []

    ref = inst.get_ref()
    bin_op = BinOp(None)
    bin_op.op = '='
    bin_op.lhs.add_inst(ref)
    bin_op.rhs.add_inst(rhs)

    # If the declartion was ignored, also ignore the initialization
    bin_op.bpf_ignore = clone.bpf_ignore

    blk.append(clone)
    return bin_op


def _assign_block_to(blk, ref):
    assert len(blk.children)
    assign = BinOp.build(ref, '=', blk.children[0])
    return assign


def inst_type(inst):
    if inst.kind in (clang.CursorKind.DECL_REF_EXPR, clang.CursorKind.MEMBER_REF_EXPR, clang.CursorKind.VAR_DECL):
        return inst.type
    elif inst.kind in (clang.CursorKind.PAREN_EXPR,):
        return inst_type(inst.body.children[0])
    else:
        error(MODULE_TAG, 'ignoring some cases:', inst,inst.kind)
    return MyType.make_simple('<Unknown>', clang.TypeKind.RECORD)


def _handle_conditional_operator(inst, info):
    blk = cb_ref.get(BODY)

    # TODO: does type of body and other body match?
    # TODO: is it possible that body do not have a child?
    T = inst_type(inst.body.children[0])
    tmp_var = VarDecl.build(get_tmp_var_name(), T)
    tmp_ref = tmp_var.get_ref()
    blk.append(tmp_var)

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

    return tmp_ref


def _process_current_inst(inst, info, more):
    ctx = more.ctx

    if inst.kind == clang.CursorKind.CALL_EXPR:
        # if inst.is_func_ptr:
        #     actual = func_ptr_mapping.get(inst.name)
        #     if actual is not None:
        #         # bind function pointer to an actual function
        #         report(f'Function {inst.name} is replaced with {actual}')
        #         inst.name = actual
        #         inst.is_func_ptr = False

        # TODO: shoud it not be RHS ??
        if ctx in (ARG, LHS):
            if inst.is_operator:
                # Let's not mess up with operators
                return inst
            return _move_function_out(inst, info, more)
    elif inst.kind == clang.CursorKind.VAR_DECL:
        if inst.has_children():
            return _separate_var_decl_and_init(inst, info, more)
    elif inst.kind == clang.CursorKind.CONDITIONAL_OPERATOR:
        return _handle_conditional_operator(inst, info)

    return inst


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
    new_children = []

    with cb_ref.new_ref(ctx, parent_list):
        # Process current instruction
        inst = _process_current_inst(inst, info, more)
        if inst is None:
            # This instruction should be removed
            return None

        # Continue deeper
        for child, tag in inst.get_children_context_marked():
            if isinstance(child, list):
                new_child = []
                for i in child:
                    obj = PassObject.pack(lvl+1, tag, new_child)
                    new_inst = _do_pass(i, info, obj)
                    if new_inst is not None:
                        new_child.append(new_inst)
            else:
                obj = PassObject.pack(lvl+1, tag, parent_list)
                new_child = _do_pass(child, info, obj)
            new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def linear_code_pass(inst, info, more):
    res = _do_pass(inst, info, more)
    # Make sure all the void functions are terminated with Return instructions
    # Other functions must return something so the compiler should complain.
    for func in Function.directory.values():
        if not func.is_used_in_bpf_code:
            continue
        debug(func.name)
        func.body = _do_pass(func.body, info, PassObject())
        if not func.is_empty() and func.return_type.spelling == 'void':
            _make_sure_void_func_return(func, info)
    return res
