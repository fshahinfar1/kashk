import itertools
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code
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
                # TODO: I am converting instructions to code early because I am
                # using a string template and not an Instruction template.
                # It would be better to use the latter.
                ref, _ = gen_code(inst.array_ref, info)
                index, _  = gen_code(inst.index, info)
                size = f'sizoef({inst.type.spelling})'
                R.append((ref, index, size))
            return True
    elif inst.kind == clang.CursorKind.UNARY_OPERATOR:
        if inst.op == '*' and is_bpf_ctx_ptr(inst.child.children[0], info):
            if R is not None:
                R.append(('x', 0, 0))
            return True
    elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
        # Debug:
        # report_on_cursor(inst.cursor)
        # debug(inst.name, inst.owner)

        # TODO: what if there are multiple member access?
        owner = inst.owner[-1]
        sym = info.sym_tbl.lookup(owner)
        if sym.is_bpf_ctx:
            # We are accessing BPF context
            size = f'sizeof({inst.cursor.type.spelling})'
            R.append((sym.name, 0, size))
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


# TODO: This design is very bad. I should generate a new set of instructions
# instead of modifying the exisiting set.
# TODO: it is dangerous to change the list I am iterating!
# TODO: I am sad about implementation choices I made!!
def add_verifier_checks(insts, info):
    new_set_of_insts = []
    q = []

    # This is for tracking the position of currenct instructions
    last_block = []
    current_index_in_block = []
    cur_context = None

    q.append((END_BLOCK, (BODY, None)))
    for i in reversed(insts):
        q.append((i, 0))
    q.append((NEW_BLOCK, (BODY, insts)))

    while q:
        inst, lvl = q.pop()

        if inst == END_DEPTH and lvl is None:
            current_index_in_block[-1] += 1
            continue
        elif inst == NEW_BLOCK:
            if lvl[0] == BODY:
                last_block.append(lvl[1])
                current_index_in_block.append(0)
            cur_context = lvl[0]
            continue
        elif inst == END_BLOCK:
            if lvl[0] == BODY:
                last_block.pop()
                current_index_in_block.pop()
            cur_context = lvl[1]
            continue

        # debug('  '*lvl, inst, current_index_in_block[-1], cur_context)

        # Assignment
        if inst.kind == clang.CursorKind.BINARY_OPERATOR:
            lhs = inst.lhs[0]
            rhs = inst.rhs[0]
            # Track which variables are pointer to the BPF context
            if inst.op == '=':
                lhs_is_ptr = is_bpf_ctx_ptr(lhs, info)
                rhs_is_ptr = is_bpf_ctx_ptr(rhs, info)
                # TODO: it can also be a MEMBER_REF
                if inst.lhs[0].kind == clang.CursorKind.DECL_REF_EXPR:
                    if rhs_is_ptr:
                        sym = info.sym_tbl.lookup(lhs.name)
                        sym.is_bpf_ctx = True
                        debug(sym.name, 'is ctx ptr')
                    elif not rhs_is_ptr and lhs_is_ptr:
                        sym = info.sym_tbl.lookup(lhs.name)
                        sym.is_bpf_ctx = False
                        debug(sym.name, 'is something else')

            # Check if the BPF context is accessed
            # TODO: this API is awful

            R = []
            lhs_is_from_ctx = is_value_from_bpf_ctx(lhs, info, R)
            if lhs_is_from_ctx:
                ref, index, T = R.pop()
                check = f'if ((void *)({ref} + {index} + 1)) > (void *)(__u64)skb->data_end ) {{\nreturn 0;\n}}\n'
                inst = Instruction()
                inst.kind = CODE_LITERAL
                inst.text = check

                loc = current_index_in_block[-1]
                blk = last_block[-1]
                # Add the check a line before this access
                blk.insert(loc, inst)


                debug('~~~~~~~~~~~~~~~~~~')
                debug(check)
                # for b in blk:
                #     debug(b)
                debug('loc:', loc, 'len block:', len(blk))
                inst = blk[loc]
                _tmp_text, _ = gen_code([inst], info)
                debug('inst:', _tmp_text)
                debug('~~~~~~~~~~~~~~~~~~')
            rhs_is_from_ctx = is_value_from_bpf_ctx(rhs, info, R)
            if rhs_is_from_ctx:
                r = R.pop()
                debug(r)


        # Step into the function
        if inst.kind == clang.CursorKind.CALL_EXPR:
            func = inst.get_function_def()
            if func:
                # Find which arguments are context pointer before switching the
                # scope
                pos_of_ctx_ptrs = []
                for pos, a in enumerate(inst.args):
                    if is_bpf_ctx_ptr(a, info):
                        pos_of_ctx_ptrs.append(pos)

                # Switch the context, then update the context flag in this
                # context
                scope = info.sym_tbl.scope_mapping.get(inst.name)
                assert scope is not None
                cur = info.sym_tbl.current_scope
                info.sym_tbl.current_scope = scope
                # debug('function call:', inst.name, 'args:', inst.args)

                for pos in pos_of_ctx_ptrs:
                    param = func.args[pos]
                    sym = info.sym_tbl.lookup(param.name)
                    sym.is_bpf_ctx = True
                    debug('function:', inst.name, 'param:', param.name, 'is bpf ctx')
                    # TODO: do I need to turn the flag off when removing
                    # the scope of the function (may in another run the
                    # parameter is not a pointer to the context)

                modified = add_verifier_checks(func.body, info)
                info.sym_tbl.current_scope = cur

        if cur_context == BODY:
            # End of processing the children of this node
            q.append((END_DEPTH, None))

        # c: list of instructions
        # tag: context tag (BODY, ARG, ...)
        for c, tag in reversed(inst.get_children_context_marked()):
            # End of the block of kind tag and return to the current context
            q.append((END_BLOCK, (tag, cur_context)))
            for i in reversed(c):
                q.append((i, lvl+1))
            q.append((NEW_BLOCK, (tag, c)))


def _handle_binop(inst, info, more):
    # debug(inst.lhs.children, inst.op, inst.rhs.children)
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
            check = bpf_ctx_bound_check(ref, index, '(__u64)skb->data_end')
            check_inst = Literal(check, CODE_LITERAL)
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
    if func:
        with info.sym_tbl.with_func_scope(inst.name):
            # Add skb as the last parameter of this function
            skb_obj = StateObject(None)
            skb_obj.name = 'skb'
            skb_obj.type = 'struct __sk_buff *'
            skb_obj.is_pointer = True
            func.args.append(skb_obj)
            T = MyType()
            T.spelling = skb_obj.type
            T.kind = clang.TypeKind.POINTER
            # TODO: probably the next line is adding the symbol information to
            # a wrong scope.
            info.sym_tbl.insert_entry(skb_obj.name, T, clang.CursorKind.PARM_DECL, None)
            skb_obj.real_type = T

            # TODO: update every invocation of this function with the skb parameter
            # TODO: what if the caller function does not have access to skb?
            skb_ref = Ref(None, kind=clang.CursorKind.DECL_REF_EXPR)
            skb_ref.name = skb_obj.name
            inst.args.append(skb_ref)

            for pos in pos_of_ctx_ptrs:
                param = func.args[pos]
                sym = info.sym_tbl.lookup(param.name)
                sym.is_bpf_ctx = True
                # debug('function:', inst.name, 'param:', param.name, 'is bpf ctx')
                # TODO: do I need to turn the flag off when removing
                # the scope of the function? (maybe in another run the
                # parameter is not a pointer to the context)

            modified = verifier_pass(func.body, info, (0, BODY, None))
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
            ref_str, _ = gen_code([ref], info)
            size_str, _ = gen_code([size], info)
            check = bpf_ctx_bound_check_bytes(ref_str, size_str, '(__u64)skb->data_end')
            check_inst = Literal(check, CODE_LITERAL)
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


# TODO:The CodeBlockRef thing is not correct and works really bad. Find a way
# to fix it.
cb_ref = CodeBlockRef()
def verifier_pass(inst, info, more):
    lvl, ctx, parent_list = more
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
                    new_inst = verifier_pass(i, info, (lvl+1, tag, new_child))
                    if new_inst is not None:
                        new_child.append(new_inst)
            else:
                new_child = verifier_pass(child, info, (lvl+1, tag, parent_list))
            new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst
