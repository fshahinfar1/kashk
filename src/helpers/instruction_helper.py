from instruction import *


def get_ret_inst(func, info=None):
    """
    Prepare appropriate return instruction based on the current function.
    """
    ret = Instruction()
    ret.kind = clang.CursorKind.RETURN_STMT
    if func is None:
        ret_val = 'DROP'
        if info is not None:
            ret_val = info.prog.get_drop()
        ret.body = [Literal(ret_val, CODE_LITERAL)]
    elif func.return_type.spelling != 'void':
        ret.body = [Literal(f'({func.return_type.spelling})0', CODE_LITERAL)]
    else:
        ret.body = []
    return ret


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
