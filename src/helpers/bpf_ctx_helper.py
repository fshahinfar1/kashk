from instruction import *
from data_structure import *
from helpers.instruction_helper import symbol_for_inst


def is_value_from_bpf_ctx(inst, info, R=None):
    """
    Check if an instruction result is a value from the BPF context memory
    region

    @param inst: the Instruction object
    @param info: the global information gathered about the program
    @param R: None or a list. If not None then the range of access would be
    written in this list. The range is formated as a tuple. Each r in R has
    three elemetns. The description of each element is as below:
        r.0 = The reference to the pointer
        r.1 = The offset to the pointer
        r.2 = The size of the access
        Access is to ptr from off to off+size.
    """
    # TODO: the cases are incomplete
    ZERO = Literal('0', CODE_LITERAL)
    if inst.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        if is_bpf_ctx_ptr(inst.array_ref, info):
            if R is not None:
                ref = inst.array_ref
                index =inst.index.children[0]
                size = Literal(f'sizoef({inst.type.spelling})', kind=CODE_LITERAL)
                R.append((ref, index, size))
            return True
    elif inst.kind == clang.CursorKind.UNARY_OPERATOR:
        if inst.op == '*' and is_bpf_ctx_ptr(inst.child.children[0], info):
            if R is not None:
                ref = inst.child.children[0]
                R.append((ref, ZERO, ZERO))
            return True
    elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
        # TODO: what if there are multiple member access?
        owner = inst.owner[-1]
        if isinstance(owner, ArrayAccess):
            # TODO: is it possible that there are nested array accesses?
            assert isinstance(owner.array_ref, Ref)
            owner = owner.array_ref
        if isinstance(owner, Cast):
            owner = owner.castee.children[0]
        assert isinstance(owner, Ref)
        # owner name is
        sym = info.sym_tbl.lookup(owner.name)
        assert sym is not None
        if sym.is_bpf_ctx:
            # We are accessing BPF context
            ref = Ref(None)
            ref.name = sym.name
            ref.type = sym.type # TODO: is sym.type an instance of MyType?
            assert isinstance(ref.type, MyType)
            ref.kind = clang.CursorKind.DECL_REF_EXPR
            index = Literal('0', clang.CursorKind.INTEGER_LITERAL)
            size = Literal(f'sizeof({inst.type.spelling})', CODE_LITERAL)
            R.append((ref, index, size))
            return True
        else:
            # TODO: how to check if each field is pointing to the bpf context?
            pass
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
        # assert sym is not None, 'What does it mean there is no symbol table entry  ??'
        if sym is None:
            error(f'Symbol for reference {inst.name} was not found in the table!')
            # debug(info.sym_tbl.current_scope.symbols)
            # assert 0
            return False
        # debug(sym.name, '--bpf ctx-->', sym.is_bpf_ctx)
        return sym.is_bpf_ctx
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
        # debug('check if castee is bpf ctx', inst.castee.children, inst.castee.children[0].kind)
        res = is_bpf_ctx_ptr(inst.castee.children[0], info)
        return res
    elif inst.kind == clang.CursorKind.PAREN_EXPR:
        return is_bpf_ctx_ptr(inst.body.children[0], info)
    elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
        # TODO: My symbol table is not keeping track of fields inside a data structure so assume it is talking about the owner
        assert len(inst.owner) > 0
        # TODO: THERE IS A BUG HERE, WHAT IF THERE ARE MULTIPLE NESTED STRUCTS? I NEED A RECURSION HERE.
        # debug("THERE IS A BUG HERE, WHAT IF THERE ARE MULTIPLE NESTED STRUCTS? I NEED A RECURSION HERE.")
        owner = inst.owner[-1]
        if not isinstance(owner, Ref):
            error('Owner is not a reference and handling this case is not implemented yet [2]')
            return
        owner_symbol = info.sym_tbl.lookup(owner.name)
        if owner_symbol is None:
            debug('DEBUG INFO:')
            debug(inst.name, inst.owner, owner.name)
            debug(info.sym_tbl.current_scope.symbols)
        assert owner_symbol is not None, f'We do not recognize the owner of member access instruction! ({owner.name})'
        sym = owner_symbol.fields.lookup(inst.name)
        # debug('mem ref:', owner.name, inst.name, ':')
        if sym is None:
            # debug('    owner does not have the field!')
            # The field is not defined before, let's just add it
            sym = owner_symbol.fields.insert_entry(inst.name, inst.type, inst.kind, None)
            return False
        else:
            # debug('    field state:', sym.is_bpf_ctx)
            pass
        assert sym is not None, 'This should be impossible'
        # debug(owner.name, '..', sym.name, '--bpf ctx-->', sym.is_bpf_ctx)
        # debug('owner symb ref:', id(owner_symbol), 'field ref:', id(sym))
        return sym.is_bpf_ctx
    return False


def set_ref_bpf_ctx_state(ref, state, info):
    """
    @param ref: object of type Ref
    @param state: bool
    """
    # debug('set', ref, 'as context:', state)
    # TODO: it can also be a MEMBER_REF

    sym = symbol_for_inst(ref, info)
    if sym is None:
        return
    sym.is_bpf_ctx = state
