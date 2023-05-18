import clang.cindex as clang

from log import error
from utility import get_code, report_on_cursor, visualize_ast, get_owner
from data_structure import *


COROUTINE_FUNC_NAME = ('await_resume', 'await_transform', 'await_ready', 'await_suspend')


def get_variable_declaration_before_elem(cursor, target_cursor):
    variables = []
    q = [cursor]
    while q:
        c = q.pop()

        if c == target_cursor:
            # Found the target element
            break

        if c.kind == clang.CursorKind.DECL_STMT:
            # Some declare statements are not declaring types or variables
            # (e.g., co_await, co_return, co_yield, ...)
            v = handle_declare_stmt(c)
            if v:
                variables.append(v)
            # We do not need to investigate the children of this node
            continue

        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)
    return variables


def handle_declare_stmt(cursor):
    """
    If the cursor points to a variable decleration, then create the proper
    object for further code generation.
    """
    children = list(cursor.get_children())
    if not children:
        return None
    var_decl = children[0]
    assert var_decl.kind == clang.CursorKind.VAR_DECL
    return VarDecl(var_decl)


def find_event_loop(cursor):
    q = [cursor]
    # Outside the connection polling loop
    while q:
        c = q.pop()

        if c.kind in (clang.CursorKind.WHILE_STMT, clang.CursorKind.DO_STMT,
                clang.CursorKind.FOR_STMT):
            # A loop found
            if __has_read(c):
                # This is the event loop
                return c


        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)
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


def gather_instructions_from(cursor, info):
    """
    Convert the cursor to a instruction
    """
    ops = []
    q = [cursor]
    # Outside the connection polling loop
    while q:
        c = q.pop()

        if c.kind == clang.CursorKind.CALL_EXPR:
            tmp_func_name = c.spelling
            if tmp_func_name in COROUTINE_FUNC_NAME:
                # Ignore these
                continue
            # A call to the function
            inst = Call(c)

            # Update name ------------------------------------
            func_name = '__this_function_name_is_not_defined__'
            if inst.is_method:
                # find the object having this method
                owners = list(reversed(inst.owner))
                func_name = []
                obj = info.scope
                for x in owners:
                    obj = obj.get(x)
                    if obj is None:
                        break
                    func_name.append(obj.type)
                    if not obj:
                        raise Exception(f'Object not found: {obj}')
                func_name.append(inst.name)
                func_name = '_'.join(func_name)
            else:
                func_name = inst.name
            inst.name = func_name
            # ------------------------------------------------

            args = []
            for x in c.get_arguments():
                arg = gather_instructions_from(x, info)
                args.extend(arg)
            inst.args = args
            ops.append(inst)

            # check if function is defined
            if inst.name not in Function.directory:
                f = Function(inst.name, inst.func_ptr)
                if f.body_cursor:
                    f.body = gather_instructions_under(f.body_cursor, info)
                info.prog.add_declaration(f)
            continue
        elif c.kind == clang.CursorKind.BINARY_OPERATOR:
            # TODO: I do not know how to get information about binary
            # operations. My idea is to parse it my self.
            inst = BinOp(c)
            children = list(c.get_children())
            assert(len(children) == 2)
            inst.lhs = gather_instructions_from(children[0], info)
            inst.rhs = gather_instructions_from(children[1], info)
            ops.append(inst)
            continue
        elif c.kind == clang.CursorKind.UNARY_OPERATOR:
            inst = UnaryOp(c)
            children = list(c.get_children())
            assert(len(children) == 1)
            inst.child = gather_instructions_from(children[0], info)
            ops.append(inst)
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
                ops.append(inst)
                info.scope.add_local(inst.name, inst.state_obj)
            else:
                error(f'Failed to add Instruction VarDecl for {c.spelling} {c.kind}')
        elif c.kind == clang.CursorKind.MEMBER_REF_EXPR:
            inst = Instruction()
            inst.cursor = c
            inst.name = c.spelling
            inst.kind = c.kind
            inst.owner = get_owner(c)[1:]
            ops.append(inst)
        elif c.kind == clang.CursorKind.DECL_REF_EXPR:
            inst = Instruction()
            inst.kind = c.kind
            inst.name = c.spelling
            ops.append(inst)
        elif c.kind in (clang.CursorKind.CXX_BOOL_LITERAL_EXPR,
                clang.CursorKind.INTEGER_LITERAL,
                clang.CursorKind.FLOATING_LITERAL,
                clang.CursorKind.STRING_LITERAL):
            inst = Instruction()
            inst.kind = c.kind
            inst.text = [t.spelling for t in c.get_tokens()][0]
            ops.append(inst)
        elif c.kind == clang.CursorKind.CONTINUE_STMT:
            inst = Instruction()
            inst.kind = c.kind
            ops.append(inst)
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

            ops.append(inst)
        elif c.kind == clang.CursorKind.DO_STMT:
            children = list(c.get_children())
            body = children[0]
            cond = children[-1]

            inst = ControlFlowInst()
            inst.kind = c.kind
            inst.cond = gather_instructions_from(cond, info)
            inst.body = gather_instructions_under(body, info)
            ops.append(inst)
        elif c.kind == clang.CursorKind.CXX_THROW_EXPR:
            inst = Instruction()
            inst.kind = c.kind
            ops.append(inst)
        elif c.kind == clang.CursorKind.COMPOUND_STMT:
            # Continue deeper
            for child in reversed(list(c.get_children())):
                q.append(child)
        elif c.kind == clang.CursorKind.UNEXPOSED_EXPR:
            # Continue deeper
            for child in reversed(list(c.get_children())):
                q.append(child)
        elif c.kind == clang.CursorKind.UNEXPOSED_STMT:
            # Some hacks
            text = get_code(c)
            if text.startswith('co_return'):
                inst = Instruction()
                inst.kind = clang.CursorKind.RETURN_STMT
                ops.append(inst)
        else:
            error('TODO:')
            report_on_cursor(c)
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
        ops += insts

    return ops
