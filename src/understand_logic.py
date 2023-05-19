import itertools
import clang.cindex as clang

from log import error
from utility import get_code, report_on_cursor, visualize_ast, get_owner
from data_structure import *
from prune import should_process_this_file

from dfs import DFSPass


def get_variable_declaration_before_elem(cursor, target_cursor, info):
    variables = []
    d = DFSPass(cursor)
    for c, _ in d:
        if c == target_cursor:
            # Found the target element
            break

        if c.kind == clang.CursorKind.VAR_DECL:
            info.sym_tbl.insert_entry(c.spelling, c.type, c.kind, c)
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

            if c.spelling == 'async_read_some':
                result.append(c)
                continue

        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)
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


def __convert_curosr_to_inst(c, info):
    if c.kind == clang.CursorKind.CALL_EXPR:
        return understand_call_expr(c, info)
    elif (c.kind == clang.CursorKind.BINARY_OPERATOR
            or c.kind == clang.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR):
        # TODO: I do not know how to get information about binary
        # operations. My idea is to parse it my self.
        inst = BinOp(c)
        children = list(c.get_children())
        assert(len(children) == 2)
        inst.lhs = gather_instructions_from(children[0], info)
        inst.rhs = gather_instructions_from(children[1], info)
        return inst
    elif (c.kind == clang.CursorKind.UNARY_OPERATOR
            or c.kind == clang.CursorKind.CXX_UNARY_EXPR):
        inst = UnaryOp(c)
        children = list(c.get_children())
        assert(len(children) == 1)
        inst.child = gather_instructions_from(children[0], info)
        return inst
    elif c.kind == clang.CursorKind.CONDITIONAL_OPERATOR:
        children = list(c.get_children())
        assert len(children) == 3
        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond = gather_instructions_from(children[0], info)
        inst.body = gather_instructions_from(children[1], info)
        inst.other_body = gather_instructions_from(children[2], info)
        return inst
    elif c.kind == clang.CursorKind.PAREN_EXPR:
        children = list(c.get_children())
        assert len(children) == 1
        inst = Instruction()
        inst.kind = c.kind
        inst.body = gather_instructions_from(children[0], info)
        return inst
    elif (c.kind == clang.CursorKind.CXX_REINTERPRET_CAST_EXPR
            or c.kind == clang.CursorKind.CSTYLE_CAST_EXPR):
        children = list(c.get_children())
        count_children = len(children)
        inst = Instruction()
        inst.kind = clang.CursorKind.CSTYLE_CAST_EXPR
        if count_children == 1:
            inst.castee = gather_instructions_from(children[0], info)
            tokens = list(map(lambda x: x.spelling, c.get_tokens()))
            assert tokens[0] == '('
            index = tokens.index(')')
            type_name = ' '.join(tokens[1:index])
            inst.cast_type = type_name
        elif count_children == 2:
            inst.castee = gather_instructions_from(children[1], info)
            inst.cast_type = children[0]
        else:
            raise Exception('Unexpected case!!')
    elif c.kind == clang.CursorKind.DECL_STMT:
        var_decl = None
        init = []
        children = list(c.get_children())
        if children[0].kind == clang.CursorKind.VAR_DECL:
            var_decl = children[0]
            children = list(var_decl.get_children())
            if children:
                init = gather_instructions_from(children[-1], info)
            inst = VarDecl(var_decl)
            inst.init = init
            info.scope.add_local(inst.name, inst.state_obj)

            # Variable Declaration
            name = var_decl.spelling
            T = var_decl.type.spelling
            entry = SymbolTableEntry(name, T, 'variable', None)
            info.sym_tbl.insert(entry)

            return inst
        else:
            error(f'Failed to add Instruction VarDecl for {c.spelling} {c.kind}')
            return None
    elif c.kind == clang.CursorKind.MEMBER_REF_EXPR:
        inst = Instruction()
        inst.cursor = c
        inst.name = c.spelling
        inst.kind = c.kind
        inst.owner = get_owner(c)[1:]
        return inst
    elif (c.kind == clang.CursorKind.DECL_REF_EXPR
            or c.kind == clang.CursorKind.TYPE_REF):
        inst = Instruction()
        inst.kind = clang.CursorKind.DECL_REF_EXPR
        inst.name = c.spelling
        return inst
    elif c.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        # print('Array sub')
        # report_on_cursor(c)

        children = list(c.get_children())
        count_children = len(children)
        assert count_children == 2

        inst = Instruction()
        inst.kind = c.kind
        inst.array_name = children[0].spelling
        inst.index = gather_instructions_from(children[1], info)
        return inst
    elif c.kind in (clang.CursorKind.CXX_BOOL_LITERAL_EXPR,
            clang.CursorKind.INTEGER_LITERAL,
            clang.CursorKind.FLOATING_LITERAL,
            clang.CursorKind.STRING_LITERAL,
            clang.CursorKind.CHARACTER_LITERAL,):
        inst = Instruction()
        inst.kind = c.kind
        # print(list(map(lambda x: x.spelling, c.get_tokens())))
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
        cond = gather_instructions_from(children[0], info)
        body = []
        other_body = []
        if len(children) > 1:
            body = gather_instructions_from(children[1], info)
        if len(children) > 2:
            other_body = gather_instructions_from(children[2], info)

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
        inst.cond = gather_instructions_from(cond, info)
        inst.body = gather_instructions_under(body, info)
        return inst
    elif c.kind == clang.CursorKind.SWITCH_STMT:
        children = list(c.get_children())
        assert len(children) == 2
        cond = gather_instructions_from(children[0], info)
        body = gather_instructions_under(children[1], info)

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
        inst.case = children[0]
        inst.body = gather_instructions_from(children[1], info)
        return inst
    elif c.kind == clang.CursorKind.DEFAULT_STMT:
        body = next(c.get_children())
        inst = Instruction()
        inst.kind = c.kind
        inst.body = gather_instructions_from(body, info)
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
            inst.body = gather_instructions_from(children[0], info)
        else:
            raise Exception('Unexpected situation when encountering RETURN_STMT')
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
            return inst
        return None
    else:
        error('TODO:')
        report_on_cursor(c)
        return None


def gather_instructions_from(cursor, info):
    """
    Convert the cursor to a instruction
    """
    ops = []
    q = [cursor]
    # Outside the connection polling loop
    while q:
        c = q.pop()

        # Check if this is a ASIO element
        if not c.location.file or not should_process_this_file(c.location.file.name):
            continue 

        if (c.kind == clang.CursorKind.COMPOUND_STMT
                or c.kind == clang.CursorKind.UNEXPOSED_EXPR):
            # Continue deeper
            for child in reversed(list(c.get_children())):
                q.append(child)
            continue
        elif c.kind == clang.CursorKind.CXX_TRY_STMT:
            # We do not have try statement in C or BPF.
            # The idea is to do what is in the try part and hope for the best!
            # TODO: Maybe do not offload try-except parts. Considering them as
            # stopping condition.

            children = list(c.get_children())
            assert len(children) > 0
            q.append(children[0])
            continue

        inst = __convert_curosr_to_inst(c, info)
        if inst:
            ops.append(inst)

    return ops


def gather_instructions_under(cursor, info):
    """
    Get the list of instruction in side a block of code.
    (Expecting the cursor to be a block of code) 
    """
    # Gather instructions in this list
    ops = []
    for c in cursor.get_children():
        insts = gather_instructions_from(c, info)
        ops.extend(insts)

    return ops


from understand_logic_handler import *
