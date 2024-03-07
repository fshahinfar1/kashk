import clang.cindex as clang
from my_type import MyType
from log import debug, error


MODULE_TAG = '[SYM TBL HELPER]'


__tmp_counter = 0
def __get_tmp_symbol_name():
    global __tmp_counter
    i = __tmp_counter
    __tmp_counter += 1
    return '__tmp_sym_name__{}'


def _handle_unary(inst, tbl):
    tmp_list = get_symbol(inst.operand)
    operand_sym = tmp_list[-1]
    if inst.op == '*':
        assert operand_sym.type.is_pointer()
        operand_mem = operand_sym.mem_entry_ref
        ref_mem_add = operand_mem.val
        assert val is not None and isinstance(val, int)
        eval_mem = tbl.memory.get(ref_mem_add)
        sym = eval_mem.associated_sym
        return tmp_list + [sym,]
    elif inst.op == '&':
        tmp_name = __get_tmp_symbol_name()
        T = MyType.make_pointer(operand_sym.type)
        sym = tbl.insert_entry(tmp_name, T,
                clang.CursorKind.UNARY_OPERATOR, None)
        mem = tbl.memory.alloc(MemEntry.REGION_NO_WHERE, T)
        mem.val = operand_mem.get_ref()
        sym.mem_entry_ref = mem
        mem.associated_sym = sym
        return tmp_list + [sym,]
    else:
        error('unary operator not implemented', tag=MODULE_TAG)
        return None


def _handle_binary(inst, tbl):
    tmp_list = get_symbol(inst.operand)
    operand_sym = tmp_list[-1]
    if inst.op == '+':
        if not operand_sym.type.is_pointer():
            error('addition on non pointer is not implemented', tag=MODULE_TAG)
            return None
        tmp_name = __get_tmp_symbol_name()
        T = MyType.make_pointer(operand_sym.type)
        sym = tbl.insert_entry(tmp_name, T,
                clang.CursorKind.BINARY_OPERATOR, None)
        mem = tbl.memory.alloc(MemEntry.REGION_NO_WHERE, T)
        debug('We are losing track of memory', tag=MODULE_TAG)
        mem.val = None
        sym.mem_entry_ref = mem
        mem.associated_sym = sym
        return tmp_list + [sym,]
    else:
        error('binary operator not implemented', tag=MODULE_TAG)
        return None


def get_symbol(inst, tbl):
    """
    Find the correct entry from the symbol table
    returns a list of symbols, the last entry would be for the requested
    instructions. The others (if any) are the owners of the instruction.
    """
    if inst.kind == clang.CursorKind.DECL_REF_EXPR:
        sym = tbl.lookup(inst.name)
        return [sym,]
    elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
        # TODO: if len == 0 it means we are referencing current
        # class in C++
        assert len(inst.owner) == 1
        owner = inst.owner[-1]
        tmp_list = get_symbol(owner)
        owner_sym = tmp_list[-1]
        sym = owner_sym.fields.lookup(inst.name)
        return tmp_list + [sym,]
    elif inst.kind == clang.CursorKind.UnaryOp:
        if inst.op not in ('*', '&'):
            error('Not implemented. What is a symbol for a unary operator?',
                    tag=MODULE_TAG)
            return None
        return _handle_unary(inst, tbl)
    elif inst.kind == clang.CursorKind.BinOp:
        if inst.op not in ('+',):
            error('binary op not implemented', tag=MODULE_TAG)
            return None
        return _handle_binary(inst, tbl)
    elif inst.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        tmp_list = get_symbol(inst.array_ref)
        arr_sym = tmp_list[-1]
        arr_mem = arr_sym.mem_entry_ref
        sym = [m.associated_sym for m in arr_mem.val]
        return tmp_list + [sym,]
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        error('symbol for call object is not implemented yet', tag=MODULE_TAG)
        return None
    else:
        raise Exception('The instruction was not expected:', inst.kind)
