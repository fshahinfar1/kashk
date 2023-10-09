import itertools
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject
from template import bpf_ctx_bound_check, bpf_ctx_bound_check_bytes

MODULE_TAG = '[Verfier Pass]'



def is_value_from_bpf_ctx(inst, info, R=None):
    """
    Check if an instruction result is a value from the BPF context memory
    region

    @param inst: the Instruction object
    @param info: the global information gathered about the program
    @param R: None or a list. If not None then the range of access would be
    written in this list.
    """
    # TODO: the cases are incomplete
    if inst.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        if is_bpf_ctx_ptr(inst.array_ref.children[0], info):
            if R is not None:
                ref = inst.array_ref.children[0]
                index =inst.index.children[0]
                size = Literal(f'sizoef({inst.type.spelling})', kind=CODE_LITERAL)
                R.append((ref, index, size))
            return True
    elif inst.kind == clang.CursorKind.UNARY_OPERATOR:
        if inst.op == '*' and is_bpf_ctx_ptr(inst.child.children[0], info):
            if R is not None:
                R.append(('x', 0, 0))
            return True
    elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
        # TODO: what if there are multiple member access?
        owner = inst.owner[-1].name
        sym = info.sym_tbl.lookup(owner)
        if not sym:
            error(MODULE_TAG, f'did not found the symbol object for {owner}')
        elif sym.is_bpf_ctx:
            # We are accessing BPF context
            ref = Ref(None)
            ref.name = sym.name
            ref.type = sym.type # TODO: is sym.type an instance of MyType?
            assert isinstance(ref.type, MyType)
            ref.kind = clang.CursorKind.DECL_REF_EXPR
            index = Literal('0', clang.CursorKind.INTEGER_LITERAL)
            size = Literal(f'sizeof({inst.cursor.type.spelling})', CODE_LITERAL)
            R.append((ref, index, size))
            return True
    return False


def is_bpf_ctx_ptr(inst, info):
    """
    Check if an instruction result is a pointer to the BPF context memory
    region
    """
    # TODO: this is incomplete
    if inst.kind == clang.CursorKind.DECL_REF_EXPR:
        # A simple variable reference
        sym = info.sym_tbl.lookup(inst.name)
        if sym:
            if sym.is_bpf_ctx:
                return True
    elif inst.kind == clang.CursorKind.BINARY_OPERATOR:
        # A pointer arithmatic or assignment
        op_is_good = inst.op in itertools.chain(BinOp.ARITH_OP, BinOp.ASSIGN_OP)
        if op_is_good:
            if (is_bpf_ctx_ptr(inst.lhs.children[0], info)
                    or is_bpf_ctx_ptr(inst.rhs.children[0], info)):
                return True
    elif inst.kind == clang.CursorKind.UNARY_OPERATOR and inst.op == '&':
        if is_value_from_bpf_ctx(inst.child.children[0], info):
            return True
    elif inst.kind == clang.CursorKind.CSTYLE_CAST_EXPR:
        if inst.cast_type.kind == clang.TypeKind.POINTER:
            res = is_bpf_ctx_ptr(inst.castee.children[0], info)
            return res
    elif inst.kind == clang.CursorKind.PAREN_EXPR:
        return is_bpf_ctx_ptr(inst.body.children[0], info)
    return False


END_DEPTH = 200
NEW_BLOCK = 201
END_BLOCK = 202


def _handle_binop(inst, info, more):
    lhs = inst.lhs.children[0]
    rhs = inst.rhs.children[0]
    # Track which variables are pointer to the BPF context
    if inst.op == '=':
        lhs_is_ptr = is_bpf_ctx_ptr(lhs, info)
        rhs_is_ptr = is_bpf_ctx_ptr(rhs, info)

        # TODO: it can also be a MEMBER_REF
        if lhs.kind == clang.CursorKind.DECL_REF_EXPR:
            if rhs_is_ptr:
                sym = info.sym_tbl.lookup(lhs.name)
                sym.is_bpf_ctx = True
                # debug(sym.name, 'is ctx ptr')
            elif not rhs_is_ptr and lhs_is_ptr:
                sym = info.sym_tbl.lookup(lhs.name)
                sym.is_bpf_ctx = False
                # debug(sym.name, 'is something else')

    # Check if the BPF context is accessed and add bound checking
    for x in [lhs, rhs]:
        # TODO: this API is awful
        R = []
        val_is_from_ctx = is_value_from_bpf_ctx(x, info, R)
        if val_is_from_ctx:
            ref, index, T = R.pop()


            # TODO: this definition is duplicated through this file! do something better
            skb_ref = Ref(None)
            skb_ref.name = 'skb'
            skb_ref.kind = clang.CursorKind.DECL_REF_EXPR
            skb_ref.type = BASE_TYPES[SKB_PTR_TYPE]

            # (__u64)skb->data_end
            end_ref = Ref(None, kind=clang.CursorKind.MEMBER_REF_EXPR)
            end_ref.name = 'data_end'
            end_ref.owner.append(skb_ref)
            end_ref.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
            data_end = Cast()
            data_end.cast_type = '__u64'
            data_end.castee.add_inst(end_ref)
            check_inst = bpf_ctx_bound_check(ref, index, data_end)

            blk = cb_ref.get(BODY)
            # Add the check a line before this access
            blk.append(check_inst)

    # Keep the instruction unchanged
    return inst


def _handle_call(inst, info, more):
    # Are we passing BPF context pointer to the function?
    # If yest, find the position of the argument.
    pos_of_ctx_ptrs = []
    for pos, a in enumerate(inst.args):
        if is_bpf_ctx_ptr(a, info):
            pos_of_ctx_ptrs.append(pos)

    if not pos_of_ctx_ptrs:
        # We are not passing any special pointers. We do not need to
        # investigate inside of the function.
        return inst

    # Find the definition of the function and step into it
    func = inst.get_function_def()
    if func and not func.is_empty():
        with info.sym_tbl.with_func_scope(inst.name):
            T = BASE_TYPES[SKB_PTR_TYPE]
            # Add skb as the last parameter of this function
            skb_obj = StateObject(None)
            skb_obj.name = 'skb'
            skb_obj.type = T.spelling
            skb_obj.is_pointer = True
            func.args.append(skb_obj)
            # This is added to the scope of function being called
            info.sym_tbl.insert_entry(skb_obj.name, T, clang.CursorKind.PARM_DECL, None)
            skb_obj.type_ref = T

            # TODO: update every invocation of this function with the skb parameter
            # TODO: what if the caller function does not have access to skb?
            skb_ref = Ref(None, kind=clang.CursorKind.DECL_REF_EXPR)
            skb_ref.name = skb_obj.name
            skb_ref.type = T
            inst.args.append(skb_ref)

            for pos in pos_of_ctx_ptrs:
                param = func.args[pos]
                sym = info.sym_tbl.lookup(param.name)
                sym.is_bpf_ctx = True
                # debug('function:', inst.name, 'param:', param.name, 'is bpf ctx')
                # TODO: do I need to turn the flag off when removing
                # the scope of the function? (maybe in another run the
                # parameter is not a pointer to the context)

            modified = _do_pass(func.body, info, PassObject())
            assert modified is not None

        # Update the instructions of the function
        func.body = modified
    else:
        if inst.name not in ('memcpy',):
            # We can not modify this function
            error(MODULE_TAG, 'function:', inst.name,
                'receives BPF context but is not accessible for modification')
        else:
            ref = inst.args[0]
            size = inst.args[2]

            # Add the check a line before this access
            skb_ref = Ref(None)
            skb_ref.name = 'skb'
            skb_ref.kind = clang.CursorKind.DECL_REF_EXPR
            skb_ref.type = BASE_TYPES[SKB_PTR_TYPE]

            end_ref = Ref(None, kind=clang.CursorKind.MEMBER_REF_EXPR)
            end_ref.name = 'data_end'
            end_ref.owner.append(skb_ref)
            data_end = Cast()
            data_end.cast_type = '__u64'
            data_end.castee.add_inst(end_ref)
            check_inst = bpf_ctx_bound_check_bytes(ref, size, data_end)

            tmp, _ = gen_code([check_inst], info)

            blk = cb_ref.get(BODY)
            blk.append(check_inst)
    return inst


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.BINARY_OPERATOR:
        return _handle_binop(inst, info, more)
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        return _handle_call(inst, info, more)
    # Ignore other instructions
    return inst


# TODO: I need to ignore instructions after the ToUserspace

# TODO:The CodeBlockRef thing is not correct and works really bad. Find a way
# to fix it.
cb_ref = CodeBlockRef()
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


def verifier_pass(inst, info, more):
    return _do_pass(inst, info, more)
