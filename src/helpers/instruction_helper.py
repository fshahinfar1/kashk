from instruction import *


def show_insts(lst, depth=0):
    """
    Visualize the tree of instructions
    """
    indent = '  '
    if isinstance(lst, Block):
        lst = lst.children
    elif isinstance(lst, Instruction):
        lst = [lst,]
    for i in lst:
        debug(indent * depth + str(i))
        if isinstance(i, list):
            show_insts(i, depth=depth+1)
        elif i.has_children():
            show_insts(i.get_children(), depth=depth+1)


def get_ret_inst(func, info=None):
    """
    Prepare appropriate return instruction based on the current function.
    """
    ret = Return()
    if func is None:
        ret_val = 'DROP'
        if info is not None:
            ret_val = info.prog.get_drop()
        ret.body.add_inst(Literal(ret_val, CODE_LITERAL))
    elif func.return_type.spelling != 'void':
        ret.body.add_inst(Literal(f'({func.return_type.spelling})0', CODE_LITERAL))
    return ret


def get_ret_value_text(func, info):
    __tmp = get_ret_inst(func, info)
    if __tmp.body.has_children():
        return_val = __tmp.body.children[0].text
    else:
        return_val = ''
    return return_val


def is_variable(inst):
    """
    Check if the instruction has constant or variable value
    """
    if isinstance(inst, Ref):
        return True
    elif isinstance(inst, BinOp):
        return is_variable(inst.lhs.children[0]) or is_variable(inst.rhs.children[0])
    elif isinstance(inst, UnaryOp):
        return is_variable(inst.child.children[0])
    elif isinstance(inst, Literal):
        if inst.kind == CODE_LITERAL:
            # TODO: the code literal is a mess we do not know what is happening
            #       But this Literal instruction does not have enough
            #       information about the type and other things so we need to
            #       revise the code and not use this.
            return False
        else:
            return False

def get_scalar_variables(inst):
    """
    As in BPF verifier fashion, variables have 3 types.
    Non_init, Scalar, and Pointer. Get every thing in the instruction that is
    variable (meaning not constant) and a Scalar (not pointer).

    @returns a list of objects of type Ref(Instruction)
    """
    # TODO: the set of conditions handled in this function is incomplete!
    if inst.kind in (BLOCK_OF_CODE,
            clang.CursorKind.CSTYLE_CAST_EXPR,
            clang.CursorKind.UNARY_OPERATOR,
            clang.CursorKind.BINARY_OPERATOR,
            clang.CursorKind.PAREN_EXPR):
        res = []
        for c in inst.get_children():
            res += get_scalar_variables(c)
        return res
    elif isinstance(inst, Ref):
        print(inst)
        if inst.type.is_pointer() or inst.type.is_array():
            return []
        else:
            return [inst,]
    else:
        return []


def get_ref_symbol(ref, info):
    """
    Get the symbol entry of a Ref object from the symbol table.
    This function handles the case which a reference is a member of another
    reference.
    """
    if ref.is_member():
        owner_sym = None
        scope     = info.sym_tbl.current_scope
        assert scope.lookup(ref.owner[-1].name) is not None, 'The argument parent should be recognized in the caller scope'
        for o in reversed(ref.owner):
            owner_sym = scope.lookup(o.name)
            if owner_sym is None:
                owner_sym = scope.insert_entry(o.name, o.type, o.kind, None)
            scope = owner_sym.fields

        sym = scope.lookup(ref.name)
        if sym is None:
            sym = scope.insert_entry(ref.name, ref.type, ref.kind, None)
        return sym
    else:
        return info.sym_tbl.lookup(ref.name)
