from data_structure import *
from instruction import *
from my_type import MyType
from utility import get_tmp_var_name


ZERO = Literal('0', clang.CursorKind.INTEGER_LITERAL)
ONE  = Literal('1', clang.CursorKind.INTEGER_LITERAL)
NULL = Literal('NULL', clang.CursorKind.MACRO_INSTANTIATION)
NULL_CHAR = Literal("'\\0'", clang.CursorKind.INTEGER_LITERAL);

CHAR_PTR = MyType.make_pointer(BASE_TYPES[clang.TypeKind.UCHAR])
UINT = BASE_TYPES[clang.TypeKind.UINT]
INT  = BASE_TYPES[clang.TypeKind.INT]
U64  = BASE_TYPES[clang.TypeKind.ULONGLONG]
VOID = BASE_TYPES[clang.TypeKind.VOID]
VOID_PTR = MyType.make_pointer(VOID)
CHAR     = BASE_TYPES[clang.TypeKind.SCHAR]


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
    if inst is None:
        return []

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


def symbol_for_inst(inst, info):
    if inst.kind == clang.CursorKind.DECL_REF_EXPR:
        return info.sym_tbl.lookup(inst.name)
    elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
        # TODO: THERE IS A BUG HERE, WHAT IF THERE ARE MULTIPLE NESTED STRUCTS? I NEED A RECURSION HERE.
        # debug("THERE IS A BUG HERE, WHAT IF THERE ARE MULTIPLE NESTED STRUCTS? I NEED A RECURSION HERE.")
        owner = inst.owner[-1]
        if not isinstance(owner, Ref):
            error('Failed to find symbol: owner is not a reference and handling this case is not implemented yet')
            debug('more info:')
            debug('inst:', inst)
            debug('------------------------')
            return None
        owner_symbol = info.sym_tbl.lookup(owner.name)
        if owner_symbol is None:
            error('Did not found symbol for owner of a member refernece')
            debug('more info:')
            debug(inst.name, inst.owner, owner.name)
            debug(info.sym_tbl.current_scope.symbols)
            debug('------------------------')
            return None
        sym = owner_symbol.fields.lookup(inst.name)
        if sym is None:
            sym = owner_symbol.fields.insert_entry(inst.name, inst.type, inst.kind, None)
        return sym
    else:
        error('Can not determine symbol for given instruction (not implemented?)')
        debug('debug info:')
        debug('inst:', inst)
        from code_gen import gen_code
        text, _ = gen_code([inst,], info)
        debug('text:', text)
        debug('------------------------')
        return None


def add_flag_to_func(flag, func, info):
    if flag == Function.CTX_FLAG:
        assert func.change_applied & Function.CTX_FLAG == 0
        arg = StateObject(None)
        arg.name = info.prog.ctx
        arg.type_ref = info.prog.ctx_type
        func.args.append(arg)
        func.change_applied |= Function.CTX_FLAG
        scope = info.sym_tbl.scope_mapping.get(func.name)
        assert scope is not None
        # info.prog.add_args_to_scope(info.sym_tbl.current_scope)
        info.prog.add_args_to_scope(scope)
    else:
        raise Exception('Not implemented yet!')


def decl_new_var(T: MyType, info: Info, decl_list: list[Instruction], name:str=None) -> Ref:
    """
    Declare a new variable. The variable declaration will be added to the
    `decl_list` param.
    @returns a Ref object of the new variable
    """
    if name is None:
        tmp_name = get_tmp_var_name()
    else:
        tmp_name = name
    tmp_decl = VarDecl.build(tmp_name, T)
    decl_list.append(tmp_decl)
    tmp_decl.update_symbol_table(info.sym_tbl)
    tmp_ref = tmp_decl.get_ref()
    tmp_decl.set_modified(InstructionColor.EXTRA_STACK_ALOC)
    return tmp_ref


def simplify_inst_to_ref(inst):
    if isinstance(inst, Ref):
        return inst
    if isinstance(inst, UnaryOp):
        if inst.op not in ('*', '&'):
            # The result is not a reference
            return None
        child = inst.child.children[0]
        return simplify_inst_to_ref(child)
    return None


def get_or_decl_ref(info, name, T, init=None):
    tmp = []
    sym = info.sym_tbl.lookup(name)
    if sym is None:
        # declare and initialize __zero
        ref = decl_new_var(T, info, tmp, name=name)
        if init is not None:
            tmp[0].init.add_inst(init)
    else:
        ref = Ref.from_sym(sym)
    return ref, tmp
