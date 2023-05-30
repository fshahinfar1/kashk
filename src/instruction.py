import itertools
import clang.cindex as clang

from data_structure import StateObject, Function
from log import error, debug


CODE_LITERAL = 8081
BLOCK_OF_CODE = 8082

BODY = 0
ARG = 1
LHS = 2
RHS = 3
DEF = 4
FUNC = 5


def _generate_marked_children(groups, context):
    return tuple(zip(groups, context))


class Instruction:
    def __init__(self):
        self.kind = None

    def has_children(self):
        if hasattr(self, 'body'):
            b = getattr(self, 'body')
            if b:
                return True
        return False

    def get_children(self):
        if hasattr(self, 'body'):
            b = getattr(self, 'body')
            if b:
                return b
        return []

    def get_children_context_marked(self):
        if hasattr(self, 'body'):
            b = getattr(self, 'body')
            if b:
                return [(b, BODY)]
        return []

    def clone(self, children):
        error('clone Instruction:', self.kind)
        new = Instruction()
        # new.kind = self.kind
        for name, val in vars(self).items():
            setattr(new, name, val)
        return new

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

    def get_function_def(self):
        func = Function.directory.get(self.name)
        return func

    def clone(self, children):
        new = Call(self.cursor)
        new.name  = self.name
        new.args   = list(self.args)
        new.owner = list(self.owner)
        new.is_method = self.is_method
        new.is_operator = self.is_operator
        return new


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
        self.init = Block(ARG)
        self.is_array = c.type.kind == clang.TypeKind.CONSTANTARRAY

    def __str__(self):
        return f'<VarDecl {self.kind}: {self.type} {self.name} = {self.init}>'

    def has_children(self):
        if self.init:
            return True
        return False

    def get_children(self):
        return (self.init, )

    def get_children_context_marked(self):
        return ((self.init, ARG),)

    def clone(self, children):
        new = VarDecl(self.cursor)
        new.type = self.type
        new.name = self.name
        new.kind = self.kind
        if children:
            new.init = children[0]
        new.is_array = self.is_array
        return new


class ControlFlowInst(Instruction):
    def __init__(self):
        super().__init__()
        self.kind = None
        self.cond = Block(ARG)
        self.body = Block(BODY)
        self.other_body = Block(BODY)

    def has_children(self):
        return True

    def __str__(self):
        return f'<CtrlFlow {self.kind}: {self.cond}>'

    def get_children(self):
        return (self.cond, self.body, self.other_body)

    def get_children_context_marked(self):
        context = [ARG, BODY, BODY]
        groups = [self.cond, self.body, self.other_body]
        return _generate_marked_children(groups, context)

    def clone(self, children):
        new = ControlFlowInst()
        new.kind = self.kind
        new.cond = children[0]
        new.body = children[1]
        new.other_body = children[2]
        return new


class UnaryOp(Instruction):
    OPS = ('!', '-', '++', '--', '&', 'sizoef')

    def __init__(self, cursor):
        super().__init__()

        self.cursor = cursor
        self.kind = clang.CursorKind.UNARY_OPERATOR
        self.child = Block(ARG)
        self.op = self.__get_op()

    def __get_op(self):
        return next(self.cursor.get_tokens()).spelling

    def has_children(self):
        return True

    def get_children(self):
        return (self.child,)

    def get_children_context_marked(self):
        context = [ARG]
        groups = [self.child]
        return _generate_marked_children(groups, context)

    def clone(self, children):
        new = UnaryOp(self.cursor)
        new.op = self.op
        new.child = children[0]
        return new



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

        self.kind = clang.CursorKind.BINARY_OPERATOR
        self.lhs = Block(ARG)
        self.rhs = Block(ARG)
        self.op = ''

        if cursor is not None:
            self.__find_op_str(cursor)

        if not self.op:
            self.op = '<operation is unknown>'

    def __find_op_str(self, cursor):
        lhs_tokens = len(list(next(cursor.get_children()).get_tokens()))
        # First token after lhs
        self.op = list(cursor.get_tokens())[lhs_tokens].spelling

    def has_children(self):
        return True

    def get_children(self):
        return (self.lhs, self.rhs)

    def get_children_context_marked(self):
        context = (ARG, ARG)
        groups = (self.lhs, self.rhs)
        return _generate_marked_children(groups, context)

    def clone(self, children):
        new = BinOp(None)
        new.op = self.op
        assert isinstance(children[0], Block)
        new.lhs = children[0]
        new.rhs = children[1]
        return new


class CaseSTMT(Instruction):
    def __init__(self, cursor):
        super().__init__()
        self.kind = cursor.kind
        self.cursor = cursor
        self.case = Block(ARG)
        self.body = Block(BODY)

    def has_children(self):
        return True

    def get_children(self):
        return (self.case, self.body)

    def get_children_context_marked(self):
        context = (ARG, BODY)
        groups = (self.case, self.body)
        return _generate_marked_children(groups, context)

    def clone(self, children):
        new = CaseSTMT(self.cursor)
        new.case = children[0]
        new.body = children[1]
        return new


class ArrayAccess(Instruction):
    def __init__(self, cursor):
        super().__init__()
        self.kind = clang.CursorKind.ARRAY_SUBSCRIPT_EXPR
        self.cursor = cursor
        self.type = cursor.type
        self.array_ref = Block(ARG)
        self.index = Block(ARG)

    def has_children(self):
        return True

    def get_children(self):
        return (self.array_ref, self.index)

    def get_children_context_marked(self):
        context = (None, ARG)
        groups = (self.array_ref, self.index)
        return _generate_marked_children(groups, context)

    def clone(self, children):
        new = ArrayAccess(self.cursor)
        new.array_ref = children[0]
        new.index = children[1]
        return new


class Parenthesis(Instruction):
    def __init__(self):
        super().__init__()
        self.kind = clang.CursorKind.PAREN_EXPR
        self.body = Block(ARG)

    def has_children(self):
        return True

    def get_children(self):
        return (self.body,)

    def get_children_context_marked(self):
        return ((self.body, self.body.tag),)

    def clone(self, children):
        new = Parenthesis()
        new.body = children[0]
        return new


class Cast(Instruction):
    def __init__(self):
        super().__init__()
        self.kind = clang.CursorKind.CSTYLE_CAST_EXPR
        self.castee = Block(ARG)
        self.cast_type = None

    def has_children(self):
        return True

    def get_children(self):
        return (self.castee,)

    def get_children_context_marked(self):
        return ((self.castee, self.castee.tag),)

    def clone(self, children):
        new = Cast()
        new.cast_type = self.cast_type
        new.castee = children[0]
        return new


class Ref(Instruction):
    def __init__(self, cursor, kind=None):
        self.cursor = cursor
        self.name = cursor.spelling
        self.kind = cursor.kind if kind is None else kind
        self.owner = []

    def clone(self, _):
        new = Ref(self.cursor, self.kind)
        clone_owner = list(self.owner)
        new.owner = clone_owner
        return new


class Literal(Instruction):
    def __init__(self, text, kind):
        self.kind = kind
        self.text = text

    def clone(self, _):
        new = Literal(self.text, self.kind)
        return new

class ForLoop(Instruction):
    def __init__(self):
        self.cursor = None
        self.kind = clang.CursorKind.FOR_STMT
        self.pre = Block(ARG)
        self.cond = Block(ARG)
        self.post = Block(ARG)
        self.body = Block(BODY)

    def has_children(self):
        return True

    def get_children(self):
        return (self.pre, self.cond, self.post, self.body)

    def get_children_context_marked(self):
        context =  (ARG, ARG, ARG, BODY)
        groups = (self.pre, self.cond, self.post, self.body)
        return _generate_marked_children(groups, context)

    def clone(self, children):
        new = ForLoop()
        new.cursor = self.cursor
        new.pre = children[0]
        new.cond = children[1]
        new.post = children[2]
        new.body = children[3]
        return new


class Block(Instruction):
    def __init__(self, tag):
        super().__init__()
        self.kind = BLOCK_OF_CODE
        self.tag = tag
        self.children = []

    def add_inst(self, inst):
        self.children.appen(inst)

    def extend_inst(self, inst):
        self.children.extend(inst)

    def has_children(self):
        if self.children:
            return True
        return False

    def get_children(self):
        return list(self.children)

    def get_children_context_marked(self):
        return ((self.children, BODY),)

    def clone(self, children):
        new = Block(self.tag)
        new.children = children[0]
        return new
