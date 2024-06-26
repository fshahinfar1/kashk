from instruction import *
from data_structure import *
from my_type import MyType
from helpers.instruction_helper import symbol_for_inst, simplify_inst_to_ref, ZERO
from utility import get_top_owner

MODULE_TAG = "[BPF CTX Helper]"


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
    if inst.kind == clang.CursorKind.DECL_REF_EXPR:
        T = inst.type
        if T.is_pointer() or T.is_array():
            # It is a pointer and not an actual value
            return False
        sym = info.sym_tbl.lookup(inst.name)
        if sym is not None and sym.is_bpf_ctx:
            if R is not None:
                R.append((inst, ZERO, ZERO))
            return True
        return False
    elif inst.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        if is_bpf_ctx_ptr(inst.array_ref, info):
            if R is not None:
                ref = inst.array_ref
                index =inst.index.children[0]
                size = Literal(f'sizoef({inst.type.spelling})', kind=CODE_LITERAL)
                R.append((ref, index, size))
            return True
    elif inst.kind == clang.CursorKind.UNARY_OPERATOR:
        obj = inst.operand
        if inst.op == '*' and is_bpf_ctx_ptr(obj, info):
            if R is not None:
                R.append((obj, ZERO, ZERO))
            return True
        return False
    elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
        # TODO: what if there are multiple member access?
        owner = get_top_owner(inst)
        if isinstance(owner, ArrayAccess):
            # TODO: is it possible that there are nested array accesses?
            assert isinstance(owner.array_ref, Ref)
            owner = owner.array_ref
        if isinstance(owner, Cast):
            owner = owner.castee.children[0]
        assert isinstance(owner, Ref)
        # owner name is
        sym = info.sym_tbl.lookup(owner.name)
        if sym is None:
            error('Did not found the symbol for owner of member reference')
            debug('debug info:')
            debug('Instruction:', inst, 'Owner list:', inst.owner)
            debug('--------------------')
            return False
        if sym.is_bpf_ctx:
            # We are accessing BPF context
            ref = Ref.from_sym(sym)
            ref.original = inst.original
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
        T = inst.type
        if not (T.is_pointer() or T.is_array()):
            return False
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
    elif inst.kind == clang.CursorKind.UNARY_OPERATOR:
        obj = inst.operand
        if inst.op == '&' and is_value_from_bpf_ctx(obj, info):
            return True
        elif inst.op in ('++', '--') and is_bpf_ctx_ptr(obj, info):
            return True
        return False
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
        owner = get_top_owner(inst)
        if not isinstance(owner, Ref):
            tmp = simplify_inst_to_ref(owner)
            if tmp is None:
                error('Owner is not a reference and handling this case is not implemented yet [2]')
                return
            owner = tmp
        owner_symbol = info.sym_tbl.lookup(owner.name)
        if owner_symbol is None:
            error(f'We do not recognize the owner of member access instruction! ({owner.name})')
            debug('DEBUG INFO:')
            debug(inst.name, inst.owner, owner.name)
            debug(info.sym_tbl.current_scope.symbols)
            debug('-------------------------')
            return False
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
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        func = inst.get_function_def()
        if func is None:
            return False
        return func.may_return_bpf_ctx_ptr
    return False


def set_ref_bpf_ctx_state(ref, state, info):
    """
    @param ref: object of type Ref
    @param state: bool
    """
    # debug('set', ref, 'as context:', state)
    sym = symbol_for_inst(ref, info)
    if sym is None:
        error('Setting BPF Context Flag for the given Instruction is not implemented!', tag=MODULE_TAG)
        debug('debug info', ref, tag=MODULE_TAG)
        return
    sym.set_is_bpf_ctx(state)
