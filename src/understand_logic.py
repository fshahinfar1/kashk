import itertools
from contextlib import contextmanager
import clang.cindex as clang

from log import error
from utility import get_code, report_on_cursor, visualize_ast
from data_structure import *
from instruction import *
from prune import (should_process_this_cursor, READ_PACKET, WRITE_PACKET)
from understand_program_state import get_state_for

from dfs import DFSPass

MODULE_TAG = '[Understand Pass]'


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


def get_all_read(block):
    """
    Get all the read instructions under the cursor
    """
    result = []
    q = [block]
    # Outside the connection polling loop
    while q:
        c = q.pop()

        if c.kind == clang.CursorKind.CALL_EXPR:
            func_name = c.spelling
            if func_name in COROUTINE_FUNC_NAME:
                # These functions are for coroutine and make things complex
                continue

            if c.spelling in READ_PACKET:
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

            if c.spelling in WRITE_PACKET:
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
        inst = BinOp(c)
        children = c.get_children()
        lhs_inst = gather_instructions_from(next(children), info, context=LHS)[0]
        inst.lhs.add_inst(lhs_inst)
        rhs_inst = gather_instructions_from(next(children), info, context=RHS)[0]
        inst.rhs.add_inst(rhs_inst)
        inst.bpf_ignore = lhs_inst.bpf_ignore or rhs_inst.bpf_ignore
        return inst
    elif (c.kind == clang.CursorKind.UNARY_OPERATOR
            or c.kind == clang.CursorKind.CXX_UNARY_EXPR):
        inst = UnaryOp(c)
        child = gather_instructions_from(next(c.get_children()), info, context=ARG)
        inst.child.extend_inst(child)
        return inst
    elif c.kind == clang.CursorKind.CONDITIONAL_OPERATOR:
        children = c.get_children()
        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond.extend_inst(gather_instructions_from(next(children), info, context=ARG))
        inst.body.extend_inst(gather_instructions_from(next(children), info, context=ARG))
        inst.other_body.extend_inst(gather_instructions_from(next(children), info, context=ARG))
        return inst
    elif c.kind == clang.CursorKind.PAREN_EXPR:
        children = c.get_children()
        inst = Parenthesis()
        inst.body.extend_inst(gather_instructions_from(next(children), info, context=ARG))
        return inst
    elif (c.kind == clang.CursorKind.CXX_REINTERPRET_CAST_EXPR
            or c.kind == clang.CursorKind.CSTYLE_CAST_EXPR
            or c.kind == clang.CursorKind.CXX_STATIC_CAST_EXPR):
        children = list(c.get_children())
        count_children = len(children)
        # TODO: I do not remember why I am doing this check
        assert count_children < 3
        inst = Cast()
        inst.castee.extend_inst(gather_instructions_from(children[-1], info, context=ARG))
        inst.cast_type = c.type
        return inst
    elif c.kind == clang.CursorKind.DECL_STMT:
        children = c.get_children()
        res = gather_instructions_from(next(children), info, context=ARG)
        if res:
            return res[0]
        return None
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
            init = []
            children = list(c.get_children())
            # TODO: why there is a TYPE_REF in VAR_DECL children?
            # Get rid of TYPE_REF in the init list!
            while children and children[-1].kind == clang.CursorKind.TYPE_REF:
                children.pop()
            if children:
                init = gather_instructions_from(children[-1], info, context=ARG)

        inst.init.extend_inst(init)

        # Add variable to the scope
        if info.sym_tbl.lookup(c.spelling) is not None:
            error(f'{MODULE_TAG} Shadowing variables are not supported and can cause issues! ({c.spelling})')
        info.sym_tbl.insert_entry(inst.name, inst.type, inst.kind, None)

        # Check if there is a type dependencies which we need to define
        _, decls = get_state_for(c)
        for d in decls:
            info.prog.add_declaration(d)

        return inst
    elif c.kind == clang.CursorKind.MEMBER_REF_EXPR:
        inst = Ref(c)
        return inst
    elif (c.kind == clang.CursorKind.DECL_REF_EXPR
            or c.kind == clang.CursorKind.TYPE_REF):
        inst = Ref(c, clang.CursorKind.DECL_REF_EXPR)
        return inst
    elif c.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        children = c.get_children()

        inst = ArrayAccess(c)
        inst.array_ref.extend_inst(gather_instructions_from(next(children), info, context=ARG))
        inst.index.extend_inst(gather_instructions_from(next(children), info, context=ARG))
        return inst
    elif c.kind in (clang.CursorKind.CXX_BOOL_LITERAL_EXPR,
            clang.CursorKind.INTEGER_LITERAL,
            clang.CursorKind.FLOATING_LITERAL,
            clang.CursorKind.STRING_LITERAL,
            clang.CursorKind.CHARACTER_LITERAL,):
        try:
            token_text = next(c.get_tokens()).spelling
        except StopIteration:
            # Weirdly there are no token!
            token_text = '<token not found>'
        inst = Literal(token_text, c.kind)
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
        inst.cond.extend_inst(cond)
        inst.body.extend_inst(body)
        inst.other_body.extend_inst(other_body)
        return inst
    elif c.kind == clang.CursorKind.DO_STMT:
        children = list(c.get_children())
        body = children[0]
        cond = children[-1]
        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond.extend_inst(gather_instructions_from(cond, info, context=ARG))
        inst.body.extend_inst(gather_instructions_under(body, info, BODY))
        return inst
    elif c.kind == clang.CursorKind.WHILE_STMT:
        children = c.get_children()
        cond = next(children)
        body = next(children)
        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond.extend_inst(gather_instructions_from(cond, info, context=ARG))
        inst.body.extend_inst(gather_instructions_under(body, info, context=BODY))
        return inst
    elif c.kind == clang.CursorKind.FOR_STMT:
        children = list(c.get_children())
        # TODO: it will not work when parts of for-loop instruction is omitted. I should fix it.
        assert len(children) == 4
        inst = ForLoop()
        inst.cursor = c
        inst.pre.extend_inst(gather_instructions_from(children[0], info, context=ARG))
        inst.cond.extend_inst(gather_instructions_from(children[1], info, context=ARG))
        inst.post.extend_inst(gather_instructions_from(children[2], info, context=ARG))
        inst.body.extend_inst(gather_instructions_from(children[3], info, context=BODY))
        return inst
    elif c.kind == clang.CursorKind.SWITCH_STMT:
        children = list(c.get_children())
        assert len(children) == 2
        cond = gather_instructions_from(children[0], info, context=ARG)
        body = gather_instructions_under(children[1], info, BODY)

        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond.extend_inst(cond)
        inst.body.extend_inst(body)
        return inst
    elif c.kind == clang.CursorKind.CASE_STMT:
        children = list(c.get_children())
        inst = CaseSTMT(c)
        inst.case.extend_inst(gather_instructions_from(children[0], info, context=ARG))
        inst.body.extend_inst(gather_instructions_from(children[1], info, context=BODY))
        return inst
    elif c.kind == clang.CursorKind.DEFAULT_STMT:
        body = next(c.get_children())
        inst = CaseSTMT(c)
        inst.body.extend_inst(gather_instructions_from(body, info, context=BODY))
        return inst
    elif c.kind == clang.CursorKind.BREAK_STMT:
        inst = Instruction()
        inst.kind = c.kind
        return inst
    elif c.kind == clang.CursorKind.RETURN_STMT:
        # TODO: Return statement is not updated with Block class
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
        else:
            error('TODO:')
            report_on_cursor(c)
        return None
    elif c.kind == clang.CursorKind.UNEXPOSED_EXPR:
        children = list(c.get_children())
        if len(children) == 1:
            child = children[0]
            return  __convert_cursor_to_inst(child, info)
        else:
            error('TODO:')
            report_on_cursor(c)
    elif c.kind == clang.CursorKind.NULL_STMT:
        return None
    else:
        error('TODO:')
        report_on_cursor(c)
        return None


code_for_bpf = True
def get_global_for_bpf():
    return code_for_bpf


@contextmanager
def set_global_for_bpf(val):
    global code_for_bpf
    tmp = code_for_bpf
    code_for_bpf = val
    try:
        yield None
    finally:
        code_for_bpf = tmp


def gather_instructions_from(cursor, info, context=BODY):

    """
    Convert the cursor to a instruction
    """
    ops = []
    cb_ref.push(context, ops)
    d = DFSPass(cursor)
    for c, lvl in d:
        if not should_process_this_cursor(c):
            with set_global_for_bpf(False):
                inst = __convert_cursor_to_inst(c, info)
                if inst:
                    inst.bpf_ignore = True
                    ops.append(inst)
            continue

        if (c.kind == clang.CursorKind.COMPOUND_STMT
                or c.kind == clang.CursorKind.UNEXPOSED_EXPR):
            d.go_deep()
            continue
        elif c.kind == clang.CursorKind.CXX_TRY_STMT:
            # We do not have `try' statement in C or BPF.
            # The idea is to do what is in the try part and hope for the best!
            # TODO: Maybe do not offload try-except parts. Considering them as
            # stopping condition.

            children = list(c.get_children())
            assert len(children) > 0
            d.enque(children[0], lvl+1)
            continue

        # TODO: the info = None is a case I introduced when hacking the
        # get_owner helper function. It should be avoided. It is bad code.
        if info is not None and c.get_usr() in info.remove_cursor:
            with set_global_for_bpf(False):
                inst = __convert_cursor_to_inst(c, info)
                inst.bpf_ignore = True
        else:
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
