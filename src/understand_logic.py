import itertools
import clang.cindex as clang
from utility import get_code


class Instruction:
    def __init__(self):
        pass

    def has_children(self):
        return False


    def __str__(self):
        return f'<Inst {self.kind}>'

    def __repr__(self):
        return self.__str__()


class VarDecl(Instruction):
    def __init__(self, c):
        # TODO: get rid of cursor pointer.
        # TODO: this is because I am not following a solid design in
        # implementing things
        self.cursor = c

        self.type = c.type.spelling
        self.name = c.spelling
        self.kind = clang.CursorKind.VAR_DECL
        self.init = ''

    def get_c_code(self):
        return f'{self.type} {self.name};'

    def __str__(self):
        return f'<VarDecl {self.kind}: {self.type} {self.name} = {self.init}>'

    def __repr__(self):
        return self.__str__()


class ControlFlowInst(Instruction):
    def __init__(self):
        pass

    def has_children(self):
        return True

    def __str__(self):
        return f'<CtrlFlow {self.kind}: {self.cond}>'

    def __repr__(self):
        return self.__str__()


class BinOp(Instruction):
    REL_OP = ('>', '>=', '<', '<=', '==')
    ARITH_OP = ('+', '-', '*', '/', '++', '--')
    ASSIGN_OP = ('=', '+=', '-=', '*=', '/=', '<<=', '>>=', '&=', '|=')
    BIT_OP = ('&', '|', '<<', '>>')
    ALL_OP = tuple(itertools.chain(REL_OP, ARITH_OP, ASSIGN_OP, BIT_OP))

    OPEN_GROUP = '({['
    CLOSE_GROUP = ')}]'

    def __init__(self, cursor):
        # TODO: I do not know how to get information about binary
        # operations. My idea is to parse it my self.
        self.kind = clang.CursorKind.BINARY_OPERATOR
        text = self.__get_raw_c_code(cursor)
        tks = self.__parse(text)
        for index, t in enumerate(tks):
            if t in BinOp.ALL_OP:
                self.op = t
                self.lhs = tks[:index]
                self.rhs = tks[index+1:]
                break

    def __parse(self, text):
        """
        For some reason I was not confortable with Binary Operations using
        libclang + python bindings. This function will reconstruct the line on
        which the binary operation is and parse the line to extract the operation.
        """
        # TODO: what if the binary operation expands to multiple lines
        # TODO: the right hand side can be also another binary operations, it
        # should be recursive.
        tokens = []
        parsing_op = False
        groups = []
        tk = ''
        for c in text:
            if c in BinOp.OPEN_GROUP:
                groups.append(c)
                tk += c
            elif c in BinOp.CLOSE_GROUP:
                if groups:
                    i = BinOp.CLOSE_GROUP.index(c)
                    if groups[-1] != BinOp.OPEN_GROUP[i]:
                        raise Exception('Parser error')
                    tk += c
                    groups.pop()
                else:
                    # End of token
                    if tk:
                        tokens.append(tk)
                        tk = ''
                        parsing_op = False
            elif groups:
                tk += c
            elif c in ' \t\r\n' or c ==  ';':
                if tk:
                    tokens.append(tk)
                    tk = ''
                    parsing_op = False
            elif c in BinOp.ALL_OP:
                if not parsing_op and tk:
                    tokens.append(tk)
                    tk = ''
                tk += c
                parsing_op = True
                if tk not in BinOp.ALL_OP:
                    # It is not a operation but only some signs
                    parsing_op = False
                    # Connect it to the prev token
                    tk = tokens.pop() + tk
            else:
                tk += c
        # print(text)
        # print(tokens)
        # assert(len(tokens) == 3)
        return tokens

    def __get_raw_c_code(self, c):
        if c.location.file:
            fname = c.location.file.name
            with open(fname) as f:
                l = f.readlines()[c.location.line-1]
                text = l[c.location.column-1:]
                return text
        else:
            raise Exception('Can not find the file for Binary operation source code')

    def __str__(self):
        return f'<BinOp {self.lhs} {self.op} {self.rhs}>'

    def __repr__(self):
        return self.__str__()


def __report_on_cursor(c):
    # What are we processing?
    print(c.spelling, c.kind)
    # DEBUGING: Show every line of code
    if c.location.file:
        fname = c.location.file.name
        with open(fname) as f:
            l = f.readlines()[c.location.line-1]
            l = l.rstrip()
            print(l)
            print(' ' * (c.location.column -1) + '^')


def get_variable_declaration_before_elem(cursor, target_cursor):
    variables = []
    q = [cursor]
    while q:
        c = q.pop()
        # # What are we processing?
        # print(c.spelling, c.kind)

        # # DEBUGING: Show every line of code
        # if c.location.file:
        #     fname = c.location.file.name
        #     with open(fname) as f:
        #         l = f.readlines()[c.location.line-1]
        #         l = l.rstrip()
        #         print(l)
        #         print(' ' * (c.location.column -1) + '^')

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
        # What are we processing?
        # print(c.spelling, c.kind)

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
            if func_name in ('await_resume', 'await_transform', 'await_ready',
                    'await_suspend'):
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


def gather_instructions_from(cursor, read_buf, write_buf):
    ops = []
    q = [cursor]
    # Outside the connection polling loop
    while q:
        c = q.pop()

        if c.kind == clang.CursorKind.CALL_EXPR:
            # A call to the function
            inst = Instruction()
            inst.kind = c.kind
            inst.func_name = c.spelling
            ops.append(inst)
            print("I need the reference to function implementation")
            continue
        elif c.kind == clang.CursorKind.BINARY_OPERATOR:
            # TODO: I do not know how to get information about binary
            # operations. My idea is to parse it my self.
            inst = BinOp(c)
            # print(inst)
            ops.append(inst)
            continue
        elif c.kind == clang.CursorKind.UNARY_OPERATOR:
            inst = Instruction()
            inst.kind = c.kind
            ops.append(inst)
            print("I need more data about unary operator")
        elif c.kind == clang.CursorKind.DECL_STMT:
            var_decl = None
            init = []
            children = list(c.get_children())
            if children[0].kind == clang.CursorKind.VAR_DECL:
                var_decl = children[0]
                children = list(var_decl.get_children())
                if children:
                    init = gather_instructions_from(children[-1], read_buf, write_buf)

            inst = VarDecl(var_decl)
            inst.init = init
            ops.append(inst)
        elif c.kind == clang.CursorKind.CONTINUE_STMT:
            inst = Instruction()
            inst.kind = c.kind
            ops.append(inst)
        elif c.kind == clang.CursorKind.IF_STMT:
            children = list(c.get_children())
            body = children[1]
            print('--', children[0].spelling, children[0].kind)
            cond = gather_instructions_from(children[0], read_buf, write_buf)

            inst = ControlFlowInst()
            inst.kind = c.kind
            inst.cond = cond
            inst.body = gather_instructions_under(body, read_buf, write_buf)

            ops.append(inst)
            print("I need to find the reference to branching condition")
        elif c.kind == clang.CursorKind.DO_STMT:
            children = list(c.get_children())
            body = children[0]
            cond = children[-1]
            print('**', cond.spelling, cond.kind)

            inst = ControlFlowInst()
            inst.kind = c.kind
            inst.cond = gather_instructions_from(cond, read_buf, write_buf)
            inst.body = gather_instructions_under(body, read_buf, write_buf)
            ops.append(inst)
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
            __report_on_cursor(c)
    return ops


def gather_instructions_under(cursor, read_buf, write_buf):
    # Gather instructions in this list
    ops = []
    for c in cursor.get_children():
        insts = gather_instructions_from(c, read_buf, write_buf)
        ops += insts

    return ops
