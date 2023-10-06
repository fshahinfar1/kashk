import itertools
import clang.cindex as clang

from utility import get_owner, report_on_cursor
from data_structure import StateObject, Function, MyType
from log import error, debug


CODE_LITERAL = 8081
BLOCK_OF_CODE = 8082
TO_USERSPACE_INST = 8083
ANNOTATION_INST = 8084

BODY = 0
ARG = 1
LHS = 2
RHS = 3
DEF = 4
FUNC = 5

def get_context_name(ctx):
    return {
            BODY: 'BODY',
            ARG: 'ARG',
            LHS: 'LHS',
            RHS: 'RHS',
            DEF: 'DEF',
            FUNC: 'FUNC',
            }[ctx]



def _generate_marked_children(groups, context):
    return tuple(map(lambda x: (x, x.tag), groups))


class Instruction:
    MAY_NOT_OVERLOAD = (clang.CursorKind.BREAK_STMT, clang.CursorKind.CONTINUE_STMT, clang.CursorKind.RETURN_STMT)
    def __init__(self):
        self.kind = None
        self.bpf_ignore = False

    def has_children(self):
        if self.kind not in Instruction.MAY_NOT_OVERLOAD:
            error('Function of base class (Instruction) is running for object of kind:', self.kind, 'has_children')

        if hasattr(self, 'body'):
            b = getattr(self, 'body')
            if b:
                return True
        return False

    def get_children(self):
        if self.kind not in Instruction.MAY_NOT_OVERLOAD:
            error('base get children is running for:', self.kind)

        if hasattr(self, 'body'):
            b = getattr(self, 'body')
            if b:
                return b
        return []

    def get_children_context_marked(self):
        if self.kind not in Instruction.MAY_NOT_OVERLOAD:
            error('base get children context marked is running for:', self.kind)

        if hasattr(self, 'body'):
            b = getattr(self, 'body')
            if b:
                return [(b, BODY)]
        return []

    def clone(self, children):
        if self.kind not in Instruction.MAY_NOT_OVERLOAD:
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
        self.is_func_ptr = False

        if self.name.startswith('operator'):
            self.is_operator = True
        else:
            self.is_operator = False

        fn_def = cursor.get_definition()
        # debug(self.name, 'def:', fn_def, fn_def.kind)
        if not self.is_operator and fn_def and fn_def.kind == clang.CursorKind.CXX_METHOD:
            self.is_method = True
        else:
            self.is_method = False

        children = list(cursor.get_children())
        count_args = len(list(cursor.get_arguments()))
        count_children = len(children)
        if not self.is_operator and count_children > 0 and count_children > count_args:
            assert count_children - count_args == 1, 'Expect only one extra element more than arguments in the list of chlidren'
            mem = children[0]
            self.owner = get_owner(mem)

            if self.owner:
                ref = self.owner[0]
                ref_type = ref.type
                while ref_type.kind == clang.TypeKind.TYPEDEF:
                    ref_type = ref_type.under_type
                if ref_type.kind == clang.TypeKind.POINTER:
                    self.is_func_ptr = True

    def __str__(self):
        return f'<Call {self.name} ({self.args})>'

    def get_arguments(self):
        return list(self.args)

    def get_function_def(self):
        func = Function.directory.get(self.name)
        return func

    def has_children(self):
        return True

    def get_children(self):
        return self.args

    def get_children_context_marked(self):
        return list(zip(self.args, [ARG] * len(self.args)))

    def clone(self, children):
        new = Call(self.cursor)
        new.name  = self.name
        # new.args  = list(self.args)
        new.args  = children
        new.owner = list(self.owner)
        new.is_method = self.is_method
        new.is_operator = self.is_operator
        new.bpf_ignore = self.bpf_ignore
        return new


class VarDecl(Instruction):
    def __init__(self, c):
        super().__init__()
        if c is not None:
            # TODO: get rid of cursor pointer.
            # TODO: this is because I am not following a solid design in
            # implementing things
            self.cursor = c
            self.state_obj = StateObject(c)

            self.type = MyType.from_cursor_type(c.type)
            self.name = c.spelling
        else:
            self.cursor = None
            self.state_obj = None
            self.type = None
            self.name = ''
        self.kind = clang.CursorKind.VAR_DECL
        self.init = Block(RHS)

    @property
    def is_array(self):
        return self.type.is_array()

    @property
    def is_record(self):
        return self.type.is_record()

    def __str__(self):
        if self.has_children():
            return f'<VarDecl: {self.type} {self.name} = {self.init}>'
        else:
            return f'<VarDecl: {self.type} {self.name}>'

    def has_children(self):
        if self.init.has_children():
            return True
        return False

    def get_children(self):
        return [self.init, ]

    def get_children_context_marked(self):
        return ((self.init, ARG),)

    def clone(self, children):
        new = VarDecl(self.cursor)
        new.type = self.type
        new.name = self.name
        new.kind = self.kind
        if children:
            new.init = children[0]
        new.bpf_ignore = self.bpf_ignore
        return new


class ControlFlowInst(Instruction):

    @classmethod
    def build_if_inst(cls, condition_inst):
        obj = ControlFlowInst()
        obj.kind = clang.CursorKind.IF_STMT
        obj.cond.add_inst(condition_inst)
        return obj

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
        return [self.cond, self.body, self.other_body]

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
        new.bpf_ignore = self.bpf_ignore
        return new


class UnaryOp(Instruction):
    OPS = ('!', '-', '++', '--', '&', '*', 'sizeof', '__extension__')

    def __init__(self, cursor):
        super().__init__()

        self.kind = clang.CursorKind.UNARY_OPERATOR
        self.child = Block(ARG)
        if cursor is not None:
            self.cursor = cursor
            self.comes_after = False
            self.op = self.__get_op()
        else:
            self.cursor = None
            self.op = '<not set>'
            self.comes_after = False

    def __str__(self):
        return f'<UnaryOp {self.op}>'

    def __get_op(self):
        tokens = [t.spelling for t in self.cursor.get_tokens()]
        assert len(tokens) >= 2, f'Expected there be more than one tokens in the UnaryOp but there are {len(tokens)}\n{" ".join(tokens)}'
        candid = tokens[0]
        if candid not in UnaryOp.OPS:
            self.comes_after = True
            for candid in tokens:
                if candid in UnaryOp.OPS:
                    break
            else:
                report_on_cursor(self.cursor)
                debug(tokens)
                raise Exception('Did not found the symbol for the UnaryOp')
        return candid

    def has_children(self):
        return True

    def get_children(self):
        return [self.child,]

    def get_children_context_marked(self):
        context = [ARG]
        groups = [self.child]
        return _generate_marked_children(groups, context)

    def clone(self, children):
        """
        Clone the Unary Operator instruction
        @param children: list of cloned children (This functio will not clone the children it self)
        @returns a new UnaryOp object with representing the same instruction is this object.
        """
        new = UnaryOp(self.cursor)
        new.op = self.op
        new.child = children[0]
        new.comes_after = self.comes_after
        new.bpf_ignore = self.bpf_ignore
        return new


class BinOp(Instruction):
    REL_OP = ('>', '>=', '<', '<=', '==', '!=')
    ARITH_OP = ('+', '-', '*', '/')
    ASSIGN_OP = ('=', '+=', '-=', '*=', '/=', '<<=', '>>=', '&=', '|=')
    BIT_OP = ('&', '|', '<<', '>>')
    ALL_OP = tuple(itertools.chain(REL_OP, ARITH_OP, ASSIGN_OP, BIT_OP))

    OPEN_GROUP = '({['
    CLOSE_GROUP = ')}]'

    @classmethod
    def build_op(cls, lhs_inst, op, rhs_inst):
        assert op in BinOp.ALL_OP, f'Unexpected binary operation requseted ({op})'
        obj = BinOp(None)
        obj.lhs.add_inst(lhs_inst)
        obj.op = op
        obj.rhs.add_inst(rhs_inst)
        return obj

    def __init__(self, cursor):
        super().__init__()

        self.kind = clang.CursorKind.BINARY_OPERATOR
        self.lhs = Block(LHS)
        self.rhs = Block(RHS)
        self.op = ''

        if cursor is not None:
            self.__find_op_str(cursor)

        if not self.op:
            self.op = '<operation is unknown>'

    def __str__(self):
        return f'<BinOp `{self.op}\' >'

    def __find_op_str(self, cursor):
        lhs = next(cursor.get_children())
        lhs_tokens = len(list(lhs.get_tokens()))
        # First token after lhs
        tokens = list(cursor.get_tokens())

        # debug(lhs_tokens, len(tokens), tokens)
        # report_on_cursor(cursor)

        self.op = tokens[lhs_tokens].spelling

    def has_children(self):
        return True

    def get_children(self):
        return [self.rhs, self.lhs]

    def get_children_context_marked(self):
        context = (ARG, ARG)
        groups = (self.rhs, self.lhs)
        return _generate_marked_children(groups, context)

    def clone(self, children):
        new = BinOp(None)
        new.op = self.op
        assert isinstance(children[0], Block)
        new.rhs = children[0]
        new.lhs = children[1]
        new.bpf_ignore = self.bpf_ignore
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
        return [self.case, self.body]

    def get_children_context_marked(self):
        context = (ARG, BODY)
        groups = (self.case, self.body)
        return _generate_marked_children(groups, context)

    def clone(self, children):
        new = CaseSTMT(self.cursor)
        new.case = children[0]
        new.body = children[1]
        new.bpf_ignore = self.bpf_ignore
        return new


class ArrayAccess(Instruction):
    def __init__(self, cursor):
        super().__init__()
        self.kind = clang.CursorKind.ARRAY_SUBSCRIPT_EXPR
        self.cursor = cursor
        self.type = MyType.from_cursor_type(cursor.type)
        self.array_ref = Block(ARG)
        self.index = Block(ARG)

    def has_children(self):
        return True

    def get_children(self):
        return [self.array_ref, self.index]

    def get_children_context_marked(self):
        context = (None, ARG)
        groups = (self.array_ref, self.index)
        return _generate_marked_children(groups, context)

    def clone(self, children):
        new = ArrayAccess(self.cursor)
        new.array_ref = children[0]
        new.index = children[1]
        new.bpf_ignore = self.bpf_ignore
        return new


class Parenthesis(Instruction):
    def __init__(self):
        super().__init__()
        self.kind = clang.CursorKind.PAREN_EXPR
        self.body = Block(ARG)

    def has_children(self):
        return True

    def get_children(self):
        return [self.body,]

    def get_children_context_marked(self):
        return ((self.body, self.body.tag),)

    def clone(self, children):
        new = Parenthesis()
        new.body = children[0]
        new.bpf_ignore = self.bpf_ignore
        return new


class Cast(Instruction):
    def __init__(self):
        super().__init__()
        self.kind = clang.CursorKind.CSTYLE_CAST_EXPR
        self.castee = Block(ARG)
        self.cast_type = None

    @property
    def type(self):
        return self.cast_type

    def has_children(self):
        return True

    def get_children(self):
        return [self.castee,]

    def get_children_context_marked(self):
        return ((self.castee, self.castee.tag),)

    def clone(self, children):
        new = Cast()
        new.cast_type = self.cast_type
        new.castee = children[0]
        new.bpf_ignore = self.bpf_ignore
        return new


class Ref(Instruction):
    def __init__(self, cursor, kind=None):
        super().__init__()
        self.cursor = cursor
        if cursor is None:
            self.name = '<unnamed>'
            self.kind = kind
            self.owner = []
            self.type = None
        else:
            self.name = cursor.spelling
            self.kind = cursor.kind if kind is None else kind
            self.owner = get_owner(self.cursor)
            self.type = MyType.from_cursor_type(cursor.type)
        self.variable_declaration_inst = None

    def is_func_ptr(self):
        return self.type.kind == clang.TypeKind.FUNCTIONPROTO

    def get_definition(self):
        return self.variable_declaration_inst

    def has_children(self):
        return False

    def get_children(self):
        return []

    def get_children_context_marked(self):
        return []

    def clone(self, _):
        new = Ref(self.cursor, self.kind)
        new.name = self.name
        new.type = self.type
        clone_owner = list(self.owner)
        new.owner = clone_owner
        new.bpf_ignore = self.bpf_ignore
        return new


class Literal(Instruction):
    def __init__(self, text, kind):
        super().__init__()
        self.kind = kind
        self.text = text

    def __str__(self):
        return f'<Literal {self.text}>'

    def has_children(self):
        return False

    def get_children(self):
        return []

    def get_children_context_marked(self):
        return []

    def clone(self, _):
        new = Literal(self.text, self.kind)
        new.bpf_ignore = self.bpf_ignore
        return new

class ForLoop(Instruction):
    def __init__(self):
        super().__init__()
        self.cursor = None
        self.kind = clang.CursorKind.FOR_STMT
        self.pre = Block(ARG)
        self.cond = Block(ARG)
        self.post = Block(ARG)
        self.body = Block(BODY)

    def has_children(self):
        return True

    def get_children(self):
        return [self.pre, self.cond, self.post, self.body]

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
        new.bpf_ignore = self.bpf_ignore
        return new


class Block(Instruction):
    def __init__(self, tag):
        super().__init__()
        self.kind = BLOCK_OF_CODE
        self.tag = tag
        self.children = []

    def __str__(self):
        return f'<Block>'

    def add_inst(self, inst):
        assert inst is not None
        self.children.append(inst)

    def extend_inst(self, insts):
        self.children.extend(insts)

    def has_children(self):
        if self.children:
            return True
        return False

    def get_children(self):
        return list(self.children)

    def get_children_context_marked(self):
        return ((self.children, self.tag),)

    def clone(self, children):
        new = Block(self.tag)
        new.children = children[0]
        new.bpf_ignore = self.bpf_ignore
        return new


class ToUserspace(Instruction):

    @classmethod
    def from_func_obj(cls, func):
        obj = ToUserspace()
        obj.is_bpf_main = func is None
        if func is not None:
            obj.return_type = func.return_type
        return obj

    def __init__(self):
        super().__init__()
        self.kind = TO_USERSPACE_INST
        self.is_bpf_main = False
        self.return_type = None
        self.path_id = None

    def __str__(self):
        return f'<ToUserspace>'

    def clone(self, _):
        new = ToUserspace()
        new.is_bpf_main = self.is_bpf_main
        new.return_type = self.return_type
        new.path_id = self.path_id
        new.bpf_ignore = self.bpf_ignore
        return new

    def has_children(self):
        return False

    def get_children(self):
        return []

    def get_children_context_marked(self):
        return []


class Annotation(Instruction):
    ANNOTATION_TYPE_NAME = 'struct __annotation'
    MESSAGE_FIELD_NAME = 'message'
    def __init__(self, msg=None):
        self.msg = msg[1:-1]
        self.kind = ANNOTATION_INST

    def __str__(self):
        return f'<Annotation>'

    def clone(self, _):
        # TODO: Do not need to clone :) ?! (it is goofy)
        return self

    def has_children(self):
        return False

    def get_children(self):
        return []

    def get_children_context_marked(self):
        return []
