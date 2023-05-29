import itertools
import clang.cindex as clang

from utility import get_code, get_owner, generate_struct_with_fields, report_on_cursor
from log import error, debug
from sym_table import SymbolTable


class Info:
    """
    Represents the general understanding of the program
    """
    def __init__(self):
        from bpf import SK_SKB_PROG
        self.context = None
        self.rd_buf = None
        self.wr_buf = None
        self.prog = SK_SKB_PROG()
        self.sym_tbl = SymbolTable()
        self.global_accessed_variables = set()
        self.remove_cursor = set()


class PacketBuffer:
    """
    A buffer passed to the read/write functions
    """
    def __init__(self, cursor):
        self.cursor = cursor
        self.name = cursor.spelling


class StateObject:
    def __init__(self, c):
        self.cursor = c
        self.name = c.spelling
        self.type = c.type.spelling
        self.kind = c.type.kind
        self.is_global = False
        self.type_ref = None
        self.parent_object = None

        self.is_pointer = c.type.kind == clang.TypeKind.POINTER
        if self.is_pointer:
            self.real_type = c.type.get_pointee()
        else:
            self.real_type = c.type

    def clone(self):
        if not self.cursor:
            print(self)
        new = StateObject(self.cursor)
        new.name = self.name
        new.type = self.type
        new.kind = self.kind
        new.is_global = self.is_global
        new.type_ref = self.type_ref
        new.parent_object = None
        return new

    def get(self, name):
        if self.type_ref:
            for f in self.type_ref.fields:
                if f.name == name:
                    return f

    def get_c_code(self):
        if self.real_type.kind == clang.TypeKind.CONSTANTARRAY:
            el_type = self.cursor.type.element_type.spelling
            el_count = self.cursor.type.element_count
            return f'{el_type} {self.name}[{el_count}];'
        elif self.real_type.kind == clang.TypeKind.RECORD:
            return f'struct {self.type} {self.name};'
        return f'{self.type} {self.name};'

    def __repr__(self):
        return f'<StateObject: {self.type} {self.name}>'


class TypeDefinition:
    def __init__(self, name):
        self.name = name

    def __hash__(self):
        return self.name.__hash__()

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.name == other.name
        return False

    def get_c_code(self):
        raise Exception('Not implemented')


class Elaborate(TypeDefinition):
    directory = {}

    def __init__(self, c):
        super().__init__(c.spelling)
        self.cursor = c
        if self.name not in Elaborate.directory:
            # raise Exception('Unexpected error')
            Elaborate.directory[self.name] = self

    def get_c_code(self):
        d = get_code(self.cursor)
        return '\n'+d


class Record(TypeDefinition):
    directory = {}

    def __init__(self, name, fields):
        super().__init__(name)
        self.fields = fields
        # if self.name in Record.directory:
        #     raise Exception('Unexpected error')
        Record.directory[self.name] = self

    def get_c_code(self):
        return '\n'+generate_struct_with_fields(self.name, self.fields)


class Function(TypeDefinition):
    directory = {}
    def __init__(self, name, c):
        super().__init__(name)

        # Make sure it is the function definition
        if not c.is_definition():
            tmp_cursor = c.get_definition()
            if tmp_cursor:
                c = tmp_cursor
        self.cursor = c

        if c.is_definition():
            children = list(c.get_children())
            body = children[-1]
            while body.kind == clang.CursorKind.UNEXPOSED_STMT:
                body = next(body.get_children())
            # print(name)
            # print([(x.spelling, x.kind) for x in children])
            assert (body.kind == clang.CursorKind.COMPOUND_STMT)
        else:
            body = None
        self.body_cursor = body
        self.body = []

        self.args = [StateObject(a) for a in c.get_arguments()]

        self.return_type = self.cursor.result_type.spelling

        self.is_method = False

        if self.name in Function.directory:
            raise Exception(f'Function is already defined ({self.name})')
        Function.directory[self.name] = self

    def get_c_code(self):
        # raise Exception('Not implemented')
        return f'// [[ definition of function {self.name} ]]'


class Instruction:
    def __init__(self):
        pass

    def has_children(self):
        return False


    def __str__(self):
        return f'<Inst {self.kind}>'

    def __repr__(self):
        return self.__str__()


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
        self.is_method = False
        self.is_operator = False

        children = list(cursor.get_children())
        # TODO: operator should have some sign after it. Fix this, a function name operator can confuse the code.
        if len(children) > 0 and (children[0].kind == clang.CursorKind.MEMBER_REF_EXPR):
            mem = children[0]
            self.owner = get_owner(mem)
            self.is_method = True

        if self.name.startswith('operator'):
            self.is_operator = True

    def __str__(self):
        return f'<Call {self.name} ({self.args})>'


class VarDecl(Instruction):
    def __init__(self, c):
        super().__init__()

        # TODO: get rid of cursor pointer.
        # TODO: this is because I am not following a solid design in
        # implementing things
        self.cursor = c

        self.state_obj = StateObject(c)

        self.type = c.type.spelling
        self.name = c.spelling
        self.kind = clang.CursorKind.VAR_DECL
        self.init = []
        self.is_array = c.type.kind == clang.TypeKind.CONSTANTARRAY

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


class UnaryOp(Instruction):
    OPS = ('!', '-', '++', '--', '!', '&', 'sizoef')

    def __init__(self, cursor):
        super().__init__()

        self.cursor = cursor
        self.kind = clang.CursorKind.UNARY_OPERATOR
        self.child = []
        self.op = self.__get_op()

    def __get_op(self):
        return next(self.cursor.get_tokens()).spelling

class BinOp(Instruction):
    REL_OP = ('>', '>=', '<', '<=', '==')
    ARITH_OP = ('+', '-', '*', '/')
    ASSIGN_OP = ('=', '+=', '-=', '*=', '/=', '<<=', '>>=', '&=', '|=')
    BIT_OP = ('&', '|', '<<', '>>')
    ALL_OP = tuple(itertools.chain(REL_OP, ARITH_OP, ASSIGN_OP, BIT_OP))

    OPEN_GROUP = '({['
    CLOSE_GROUP = ')}]'

    def __init__(self, cursor):
        super().__init__()

        # TODO: I do not know how to get information about binary
        # operations. My idea is to parse it my self.
        self.kind = clang.CursorKind.BINARY_OPERATOR
        self.lhs = []
        self.rhs = []
        self.op = ''

        lhs_tokens = len(list(next(cursor.get_children()).get_tokens()))
        # First token after lhs
        self.op = list(cursor.get_tokens())[lhs_tokens].spelling

        # text = self.__get_raw_c_code(cursor)
        # tks = self.__parse(text)
        # for index, t in enumerate(tks):
        #     if t in BinOp.ALL_OP:
        #         self.op = t
        #         break

        if not self.op:
            self.op = '<operation is unknown>'

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


class ContextInfo:
    KindFunction = 0
    KindClass = 1

    def __init__(self, kind, ref):
        self.kind = kind
        self.ref = ref
        pass

    def __str__(self):
        if self.kind == self.KindFunction:
            return 'Function Context'
        elif self.kind == self.KindClass:
            return 'Class Context'
        return 'Unknown Context'
