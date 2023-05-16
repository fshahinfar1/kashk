import itertools
import clang.cindex as clang
from utility import get_code, report_on_cursor, visualize_ast

COROUTINE_FUNC_NAME = ('await_resume', 'await_transform', 'await_ready', 'await_suspend')


class Instruction:
    def __init__(self):
        pass

    def has_children(self):
        return False


    def __str__(self):
        return f'<Inst {self.kind}>'

    def __repr__(self):
        return self.__str__()

    def get_c_code(self):
        return [str(self)]


class Call(Instruction):
    def __init__(self, cursor):
        super().__init__()

        self.cursor = cursor
        self.kind = clang.CursorKind.CALL_EXPR
        self.name = cursor.spelling
        self.func_ptr = cursor.referenced
        self.args = []
        # The last element of owner should be an object accesible from
        # local or global scope. The other elements would recursivly show the
        # fields in the object.
        self.owner = []

        children = list(cursor.get_children())
        if len(children) > 0 and children[0].kind == clang.CursorKind.MEMBER_REF_EXPR:
            self.is_method = True
            mem = children[0]
            self.owner = get_owner(mem)

    def __str__(self):
        return f'<Call {self.name} ({self.args})>'

    def get_c_code(self):
        a= ', '.join([x.get_c_code() for x in self.args])
        return [f'{self.name}({a});']


class VarDecl(Instruction):
    def __init__(self, c):
        super().__init__()

        # TODO: get rid of cursor pointer.
        # TODO: this is because I am not following a solid design in
        # implementing things
        self.cursor = c

        self.type = c.type.spelling
        self.name = c.spelling
        self.kind = clang.CursorKind.VAR_DECL
        self.init = ''

    def get_c_code(self):
        return [f'{self.type} {self.name};']

    def __str__(self):
        return f'<VarDecl {self.kind}: {self.type} {self.name} = {self.init}>'


class ControlFlowInst(Instruction):
    def __init__(self):
        super().__init__()
        self.kind = None
        self.cond = []
        self.body = []
        self.other_body = []
        pass

    def has_children(self):
        return True

    def __str__(self):
        return f'<CtrlFlow {self.kind}: {self.cond}>'

    def get_c_code(self):
        if self.kind == clang.CursorKind.IF_STMT:
            text = [f'if ({self.cond}) {{', 
                    [x.get_c_code() for x in self.body], 
                    '}']
            if self.other_body:
                text += ['else {\n',
                        [x.get_c_code() for x in self.other_body],
                        '}']
            return text
        elif self.kind == clang.CursorKind.DO_STMT:
            text = ['do {',
                    [x.get_c_code() for x in self.body],
                    f'\n}} while ({self.cond});']
            return text
        return [str(self)]


class BinOp(Instruction):
    REL_OP = ('>', '>=', '<', '<=', '==')
    ARITH_OP = ('+', '-', '*', '/', '++', '--')
    ASSIGN_OP = ('=', '+=', '-=', '*=', '/=', '<<=', '>>=', '&=', '|=')
    BIT_OP = ('&', '|', '<<', '>>')
    ALL_OP = tuple(itertools.chain(REL_OP, ARITH_OP, ASSIGN_OP, BIT_OP))

    OPEN_GROUP = '({['
    CLOSE_GROUP = ')}]'

    def __init__(self, cursor):
        super().__init__()

        # print('BIN OP ------------------')
        # visualize_ast(cursor)
        # print('-------------------------')

        # TODO: I do not know how to get information about binary
        # operations. My idea is to parse it my self.
        self.kind = clang.CursorKind.BINARY_OPERATOR

        text = self.__get_raw_c_code(cursor)
        tks = self.__parse(text)
        # print(tks)
        for index, t in enumerate(tks):
            if t in BinOp.ALL_OP:
                self.op = t
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
                    parsing_op = False
                tk += c
                parsing_op = True
                if tk not in BinOp.ALL_OP:
                    # It is not a operation but only some signs
                    parsing_op = False
                    # Connect it to the prev token
                    tk = tokens.pop() + tk
            elif parsing_op:
                # End of operator
                tokens.append(tk)
                tk = ''
                parsing_op = False
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
            if c.spelling in COROUTINE_FUNC_NAME:
                # Ignore these
                continue
            # A call to the function
            inst = Call(c)
            args = []
            for x in cursor.get_arguments():
                arg = gather_instructions_from(x, info)
                args.append(arg)
            inst.args = args

            ops.append(inst)
            continue
        elif c.kind == clang.CursorKind.BINARY_OPERATOR:
            # TODO: I do not know how to get information about binary
            # operations. My idea is to parse it my self.
            inst = BinOp(c)
            children = list(c.get_children())
            assert(len(children) == 2)
            inst.lhs = gather_instructions_from(children[0], info)
            inst.rhs = gather_instructions_from(children[1], info)
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
                    init = gather_instructions_from(children[-1], info)

            inst = VarDecl(var_decl)
            inst.init = init
            ops.append(inst)
            info.scope.add_local(inst.name, inst)
        elif c.kind == clang.CursorKind.DECL_REF_EXPR:
            inst = Instruction()
            inst.kind = c.kind
            inst.name = c.spelling
            ops.append(inst)
        elif c.kind in (clang.CursorKind.CXX_BOOL_LITERAL_EXPR,
                clang.CursorKind.INTEGER_LITERAL,
                clang.CursorKind.FLOATING_LITERAL):
            inst = Instruction()
            inst.kind = c.kind
            ops.append(inst)
            print('Need more about bool/int/float literal')
        elif c.kind == clang.CursorKind.CONTINUE_STMT:
            inst = Instruction()
            inst.kind = c.kind
            ops.append(inst)
        elif c.kind == clang.CursorKind.IF_STMT:
            children = list(c.get_children())
            # print('if-stmt', children)
            # print('--', children[0].spelling, children[0].kind)
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
            print("I need to find the reference to branching condition")
        elif c.kind == clang.CursorKind.DO_STMT:
            children = list(c.get_children())
            body = children[0]
            cond = children[-1]

            inst = ControlFlowInst()
            inst.kind = c.kind
            inst.cond = gather_instructions_from(cond, info)
            inst.body = gather_instructions_under(body, info)
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

def get_owner(cursor):
    # report_on_cursor(cursor)
    # print('---', cursor.kind)

    res = []
    children = list(cursor.get_children())
    assert len(children) > 0
    parent = children[0]
    if parent.kind == clang.CursorKind.DECL_REF_EXPR: 
        res.append(parent.spelling)
    if parent.kind == clang.CursorKind.MEMBER_REF_EXPR:
        res.append(parent.spelling)
        res += get_owner(parent)
    elif (parent.kind == clang.CursorKind.CALL_EXPR and
            parent.spelling == 'operator->'):
        # do not add this one
        res += get_owner(parent)
    elif parent.kind == clang.CursorKind.UNEXPOSED_EXPR:
        # res.append(parent.spelling)
        res += get_owner(parent)

    # print('owner: ', res)
    return res
