import itertools
from contextlib import contextmanager
import clang.cindex as clang

from log import error
from utility import get_code, report_on_cursor, visualize_ast, get_owner
from data_structure import *
from prune import (should_process_this_file, READ_PACKET, WRITE_PACKET)
from understand_program_state import get_state_for

from dfs import DFSPass

from bpf_code_gen import BODY, ARG, LHS, RHS, DEF, FUNC


class CodeBlockRef:
    """
    This class can hold the reference to different code blocks.
    For example current function, current class, current block, ...
    """
    def __init__(self):
        self.code_block_reference = {}
        self.stack = []

    def push(self, name, code):
        pair = (name, self.code_block_reference.get(name))
        self.stack.append(pair)
        self.code_block_reference[name] = code

    def pop(self):
        name, code = self.stack.pop()
        self.code_block_reference[name] = code

    def get(self, name, default=None):
        return self.code_block_reference.get(name, default)

    @contextmanager
    def new_ref(self, name, code):
        self.push(name, code)
        try:
            yield self
        finally:
            self.pop()


cb_ref = CodeBlockRef()


def get_variable_declaration_before_elem(cursor, target_cursor, info):
    variables = []
    d = DFSPass(cursor)
    for c, _ in d:
        if c == target_cursor:
            # Found the target element
            break

        if c.kind == clang.CursorKind.VAR_DECL:
            v = VarDecl(c)
            variables.append(v)

        d.go_deep()
    return variables


def find_event_loop(cursor):
    d = DFSPass(cursor)
    for c, _ in d:
        if c.kind in (clang.CursorKind.WHILE_STMT, clang.CursorKind.DO_STMT,
                clang.CursorKind.FOR_STMT):
            # A loop found
            if __has_read(c):
                # This is the event loop
                return c
        d.go_deep()
    return None


def get_all_read(cursor):
    """
    Get all the read instructions under the cursor
    """
    result = []
    q = [cursor]
    # Outside the connection polling loop
    while q:
        c = q.pop()

        if c.kind == clang.CursorKind.CALL_EXPR:
            func_name = c.spelling
            if func_name in COROUTINE_FUNC_NAME:
                # These functions are for coroutine and make things complex
                continue

            if c.spelling == READ_PACKET:
                result.append(c)
                continue

        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)
    return result


def get_all_send(cursor):
    """
    Get all the send system calls under the cursor
    """
    result = []
    d = DFSPass(cursor)
    # Outside the connection polling loop
    for c, _ in d:
        if c.kind == clang.CursorKind.CALL_EXPR:
            func_name = c.spelling
            if func_name in COROUTINE_FUNC_NAME:
                # These functions are for coroutine and make things complex
                continue

            if c.spelling == WRITE_PACKET:
                result.append(c)
                continue

        d.go_deep()
    return result


def __has_read(cursor):
    q = [cursor]
    # Outside the connection polling loop
    while q:
        c = q.pop()
        if c.kind == clang.CursorKind.CALL_EXPR:
            if c.spelling == 'async_read_some':
                return True


        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)
    return False


def __convert_cursor_to_inst(c, info):
    if c.kind == clang.CursorKind.CALL_EXPR:
        return understand_call_expr(c, info)
    elif (c.kind == clang.CursorKind.BINARY_OPERATOR
            or c.kind == clang.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR):
        # TODO: I do not know how to get information about binary
        # operations. My idea is to parse it my self.
        inst = BinOp(c)
        children = list(c.get_children())
        assert(len(children) == 2)
        inst.lhs = gather_instructions_from(children[0], info, context=LHS)
        inst.rhs = gather_instructions_from(children[1], info, context=RHS)
        return inst
    elif (c.kind == clang.CursorKind.UNARY_OPERATOR
            or c.kind == clang.CursorKind.CXX_UNARY_EXPR):
        inst = UnaryOp(c)
        children = list(c.get_children())
        assert(len(children) == 1)
        inst.child = gather_instructions_from(children[0], info, context=ARG)
        return inst
    elif c.kind == clang.CursorKind.CONDITIONAL_OPERATOR:
        children = list(c.get_children())
        assert len(children) == 3
        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond = gather_instructions_from(children[0], info, context=ARG)
        inst.body = gather_instructions_from(children[1], info, context=ARG)
        inst.other_body = gather_instructions_from(children[2], info, context=ARG)
        return inst
    elif c.kind == clang.CursorKind.PAREN_EXPR:
        children = list(c.get_children())
        assert len(children) == 1
        inst = Instruction()
        inst.kind = c.kind
        inst.body = gather_instructions_from(children[0], info, context=ARG)
        return inst
    elif (c.kind == clang.CursorKind.CXX_REINTERPRET_CAST_EXPR
            or c.kind == clang.CursorKind.CSTYLE_CAST_EXPR):
        children = list(c.get_children())
        count_children = len(children)
        inst = Instruction()
        inst.kind = clang.CursorKind.CSTYLE_CAST_EXPR
        if count_children == 1:
            inst.castee = gather_instructions_from(children[0], info, context=ARG)
            tokens = list(map(lambda x: x.spelling, c.get_tokens()))
            assert tokens[0] == '('
            index = tokens.index(')')
            type_name = ' '.join(tokens[1:index])
            inst.cast_type = type_name
        elif count_children == 2:
            inst.castee = gather_instructions_from(children[1], info, context=ARG)
            inst.cast_type = c.type
        else:
            raise Exception('Unexpected case!!')
        return inst
    elif c.kind == clang.CursorKind.DECL_STMT:
        children = list(c.get_children())
        assert len(children) == 1
        return gather_instructions_from(children[0], info, context=ARG)[0]
    elif c.kind == clang.CursorKind.VAR_DECL:
        inst = VarDecl(c)

        # Find the variable initialization, if there is any.
        init = []
        if inst.is_array:
            for child in c.get_children():
                if child.kind == clang.CursorKind.INTEGER_LITERAL:
                    continue
                init = gather_instructions_from(child, info, context=ARG)
                break
        else:
            # NOTE: Keeping the old code, it seems to work
            init = []
            # The first child after TYPE_REF would be the initialization of the
            # variable.
            children = list(c.get_children())
            tmp_index = 0
            for i, tmp_c in enumerate(children):
                if tmp_c.kind == clang.CursorKind.TYPE_REF:
                    tmp_index = i
                    break
            tmp_index += 1
            if len(children) > tmp_index:
                # This declaration has initialization
                init = gather_instructions_from(children[-1], info, context=ARG)

        inst.init = init

        # Add variable to the scope
        info.sym_tbl.insert_entry(c.spelling, c.type, c.kind, c)

        # Check if there is a type dependencies which we need to define
        _, decls = get_state_for(c)
        for d in decls:
            info.prog.add_declaration(d)

        return inst
    elif c.kind == clang.CursorKind.MEMBER_REF_EXPR:
        inst = Instruction()
        inst.cursor = c
        inst.name = c.spelling
        inst.kind = c.kind
        inst.owner = get_owner(c)
        return inst
    elif (c.kind == clang.CursorKind.DECL_REF_EXPR
            or c.kind == clang.CursorKind.TYPE_REF):
        inst = Instruction()
        inst.kind = clang.CursorKind.DECL_REF_EXPR
        inst.name = c.spelling

        sym, scope = info.sym_tbl.lookup2(inst.name)
        is_shared = scope == info.sym_tbl.shared_scope
        if is_shared:
            # Keep track of used global variables
            info.global_accessed_variables.add(inst.name)
            sym = scope.lookup('shared')
            debug('shared symbol is defined:', sym is not None)
            if sym is None:
                # Perform a lookup on the map for globally shared values
                code = cb_ref.get(FUNC)
                new_inst = Instruction()
                new_inst.kind = clang.CursorKind.STRING_LITERAL
                new_inst.text = '''
struct shared_state *shared = NULL;
{
  int zero = 0;
  shared = bpf_map_lookup_elem(&shared_map, &zero);
}
if (!shared) {
  return SK_DROP;
}

'''
                code.append(new_inst)
        return inst
    elif c.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        children = list(c.get_children())
        count_children = len(children)
        assert count_children == 2

        inst = Instruction()
        inst.kind = c.kind
        inst.array_ref = gather_instructions_from(children[0], info, context=ARG)
        inst.index = gather_instructions_from(children[1], info, context=ARG)
        inst.cursor = c
        return inst
    elif c.kind in (clang.CursorKind.CXX_BOOL_LITERAL_EXPR,
            clang.CursorKind.INTEGER_LITERAL,
            clang.CursorKind.FLOATING_LITERAL,
            clang.CursorKind.STRING_LITERAL,
            clang.CursorKind.CHARACTER_LITERAL,):
        inst = Instruction()
        inst.kind = c.kind
        token_text = [t.spelling for t in c.get_tokens()]
        if len(token_text) == 0:
            inst.text = '<unknown>'
            error('Some literal expration has unknown')
        else:
            inst.text = token_text[0]
        return inst
    elif c.kind == clang.CursorKind.CONTINUE_STMT:
        inst = Instruction()
        inst.kind = c.kind
        return inst
    elif c.kind == clang.CursorKind.IF_STMT:
        children = list(c.get_children())
        cond = gather_instructions_from(children[0], info, context=ARG)
        body = []
        other_body = []
        if len(children) > 1:
            body = gather_instructions_from(children[1], info, context=BODY)
        if len(children) > 2:
            other_body = gather_instructions_from(children[2], info, context=BODY)

        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond = cond
        inst.body = body
        inst.other_body = other_body

        return inst
    elif c.kind == clang.CursorKind.DO_STMT:
        children = list(c.get_children())
        body = children[0]
        cond = children[-1]
        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond = gather_instructions_from(cond, info, context=ARG)
        inst.body = gather_instructions_under(body, info, BODY)
        return inst
    elif c.kind == clang.CursorKind.FOR_STMT:
        children = list(c.get_children())
        assert len(children) == 4
        inst = Instruction()
        inst.kind = c.kind
        inst.cursor = c
        inst.pre =  gather_instructions_from(children[0], info, context=ARG)
        inst.cond = gather_instructions_from(children[1], info, context=ARG)
        inst.post = gather_instructions_from(children[2], info, context=ARG)
        inst.body = gather_instructions_from(children[3], info, context=BODY)
        return inst
    elif c.kind == clang.CursorKind.SWITCH_STMT:
        children = list(c.get_children())
        assert len(children) == 2
        cond = gather_instructions_from(children[0], info, context=ARG)
        body = gather_instructions_under(children[1], info, BODY)

        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond = cond
        inst.body = body
        return inst
    elif c.kind == clang.CursorKind.CASE_STMT:
        children = list(c.get_children())
        assert len(children) == 2
        inst = Instruction()
        inst.kind = c.kind
        inst.case = gather_instructions_from(children[0], info, context=ARG)
        inst.body = gather_instructions_from(children[1], info, context=BODY)
        return inst
    elif c.kind == clang.CursorKind.DEFAULT_STMT:
        body = next(c.get_children())
        inst = Instruction()
        inst.kind = c.kind
        inst.body = gather_instructions_from(body, info, context=BODY)
        return inst
    elif c.kind == clang.CursorKind.BREAK_STMT:
        inst = Instruction()
        inst.kind = c.kind
        return inst
    elif c.kind == clang.CursorKind.RETURN_STMT:
        children = list(c.get_children())
        count_children =  len(children)
        inst = Instruction()
        inst.kind = c.kind
        if count_children == 0:
            inst.body = []
        elif count_children == 1:
            inst.body = gather_instructions_from(children[0], info, context=ARG)
        else:
            raise Exception('Unexpected situation when encountering RETURN_STMT')
        return inst
    elif c.kind == clang.CursorKind.CXX_THROW_EXPR:
        inst = Instruction()
        inst.kind = c.kind
        return inst
    elif c.kind == clang.CursorKind.UNEXPOSED_STMT:
        # Some hacks
        text = get_code(c)
        if text.startswith('co_return'):
            inst = Instruction()
            inst.kind = clang.CursorKind.RETURN_STMT
            inst.body = []
            return inst
        return None
    elif c.kind == clang.CursorKind.NULL_STMT:
        return None
    else:
        error('TODO:')
        report_on_cursor(c)
        return None


def gather_instructions_from(cursor, info, context=BODY):
    """
    Convert the cursor to a instruction
    """
    ops = []
    cb_ref.push(context, ops)
    d = DFSPass(cursor)
    for c, _ in d:
        if (not c.location.file
                or not should_process_this_file(c.location.file.name)):
            continue

        if (c.kind == clang.CursorKind.COMPOUND_STMT
                or c.kind == clang.CursorKind.UNEXPOSED_EXPR):
            d.go_deep()
            continue
        elif c.kind == clang.CursorKind.CXX_TRY_STMT:
            # We do not have try statement in C or BPF.
            # The idea is to do what is in the try part and hope for the best!
            # TODO: Maybe do not offload try-except parts. Considering them as
            # stopping condition.

            children = list(c.get_children())
            assert len(children) > 0
            d.enque(children[0])
            continue

        inst = __convert_cursor_to_inst(c, info)
        if inst:
            ops.append(inst)
    cb_ref.pop()
    return ops


def gather_instructions_under(cursor, info, context):
    """
    Get the list of instruction in side a block of code.
    (Expecting the cursor to be a block of code)
    """
    # Gather instructions in this list
    ops = []
    for c in cursor.get_children():
        insts = gather_instructions_from(c, info, context)
        ops.extend(insts)

    return ops


from understand_logic_handler import *
