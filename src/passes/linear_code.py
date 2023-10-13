from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug, report
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from passes.clone import clone_pass


MODULE_TAG = '[Linear Code Pass]'
cb_ref = CodeBlockRef()

# TODO: this is a hack, I should use a stack to associate a mapping for each
# scope. I am Lazy:) (issue is more time constraint than lazy)
func_ptr_mapping = {}

tmp_num = 100
def _get_tmp_var_name():
    global tmp_num
    name = f'_tmp_{tmp_num}'
    tmp_num += 1
    return name

def _make_sure_void_func_return(func, info):
    last_inst = func.body.children[-1]
    if last_inst.kind == clang.CursorKind.RETURN_STMT:
        # The function end with a return
        return
    ret_inst = Instruction()
    ret_inst.kind = clang.CursorKind.RETURN_STMT
    ret_inst.body = []
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
            error(MODULE_TAG, 'can not move a function that do not know the definition: ', inst.name)
            return inst
        return_type = func.return_type

    assert return_type is not None

    blk = cb_ref.get(BODY)
    assert blk is not None

    if return_type.spelling != 'void':
        tmp_var_name = _get_tmp_var_name()
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

    ref = Ref(None, kind=clang.CursorKind.DECL_REF_EXPR)
    ref.name = inst.name
    ref.type = inst.type

    bin_op = BinOp(None)
    bin_op.op = '='
    bin_op.lhs.add_inst(ref)
    bin_op.rhs.add_inst(rhs)

    # If the declartion was ignored, also ignore the initialization
    bin_op.bpf_ignore = clone.bpf_ignore

    blk.append(clone)
    return bin_op


def _process_current_inst(inst, info, more):
    ctx = more.ctx

    if inst.kind == ANNOTATION_INST:
        if inst.ann_kind == Annotation.ANN_FUNC_PTR:
            ptr, actual = inst.msg.split(Annotation.FUNC_PTR_DELIMITER)
            func_ptr_mapping[ptr] = actual

    if inst.kind == clang.CursorKind.CALL_EXPR:
        if inst.is_func_ptr:
            actual = func_ptr_mapping.get(inst.name)
            if actual is not None:
                # bind function pointer to an actual function
                report(f'Function {inst.name} is replaced with {actual}')
                inst.name = actual
                inst.is_func_ptr = False

        # TODO: shoud it not be RHS ??
        if ctx in (ARG, LHS):
            if inst.is_operator:
                # Let's not mess up with operators
                return inst
            return _move_function_out(inst, info, more)

    if inst.kind == clang.CursorKind.VAR_DECL:
        if inst.has_children():
            return _separate_var_decl_and_init(inst, info, more)

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
        body = _do_pass(func.body, info, PassObject())
        assert body is not None
        func.body = body
        if not func.is_empty() and func.return_type.spelling == 'void':
            _make_sure_void_func_return(func, info)
    return res

