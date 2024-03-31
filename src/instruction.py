import itertools
import clang.cindex as clang

from utility import get_owner, report_on_cursor, get_actual_type
from data_structure import Function, BASE_TYPES
from my_type import MyType
from log import error, debug, report
from passes.passable import PassableObject
from elements.likelihood import Likelihood


CODE_LITERAL = 8081
BLOCK_OF_CODE = 8082
TO_USERSPACE_INST = 8083
ANNOTATION_INST = 8084
PAIR_INST = 8085

BODY = 0
ARG = 1
LHS = 2
RHS = 3
DEF = 4
FUNC = 5

BRANCHING_INSTRUCTIONS = (clang.CursorKind.IF_STMT, clang.CursorKind.SWITCH_STMT,
        clang.CursorKind.CASE_STMT, clang.CursorKind.FOR_STMT,
        clang.CursorKind.WHILE_STMT, clang.CursorKind.DO_STMT,
        clang.CursorKind.CONDITIONAL_OPERATOR, clang.CursorKind.GOTO_STMT)

MAY_HAVE_BACKWARD_JUMP_INSTRUCTIONS = (clang.CursorKind.FOR_STMT,
        clang.CursorKind.WHILE_STMT, clang.CursorKind.DO_STMT,)

def get_context_name(ctx):
    return {
            BODY: 'BODY',
            ARG: 'ARG',
            LHS: 'LHS',
            RHS: 'RHS',
            DEF: 'DEF',
            FUNC: 'FUNC',
            }[ctx]



def _generate_marked_children(groups):
    return tuple(map(lambda x: (x, x.tag), groups))


def _default_clone_operation(new, old):
    new.ignore         = old.ignore
    new.change_applied = old.change_applied
    new.color          = old.color
    new.owner          = list(old.owner)
    new.removed        = old.removed[:]
    new.original       = old.original


class InstructionColor:
    ORIGINAL          = 300  # Original Instruction
    RED               = 301  # Modification (unspecified type of modification)
    CHECK             = 302
    MAP_LOOKUP        = 303
    KNOWN_FUNC_IMPL   = 304  # BPF helper functions and other functions we know
    EXTRA_STACK_ALOC  = 305
    EXTRA_MEM_ACCESS  = 306
    REMOVE_READ       = 307
    REMOVE_WRITE      = 308
    ADD_ARGUMENT      = 309
    EXTRA_ALU_OP      = 310
    MEM_COPY          = 311
    TO_USER           = 312


INSTRUCTION_COLORS = (InstructionColor.ORIGINAL, InstructionColor.RED,
        InstructionColor.CHECK, InstructionColor.MAP_LOOKUP,
        InstructionColor.KNOWN_FUNC_IMPL, InstructionColor.EXTRA_STACK_ALOC,
        InstructionColor.EXTRA_MEM_ACCESS, InstructionColor.REMOVE_READ,
        InstructionColor.REMOVE_WRITE, InstructionColor.ADD_ARGUMENT,
        InstructionColor.EXTRA_ALU_OP, InstructionColor.MEM_COPY,
        InstructionColor.TO_USER)


# INSTRUCTION_FLAGS = (Instruction.BOUND_CHECK_FLAG,
#         Instruction.OFFSET_MASK_FLAG)

class Instruction(PassableObject):
    __slots__ = ('change_applied', 'color', 'body', 'owner', 'removed', 'original')

    BOUND_CHECK_FLAG = 1 << 3 # Have I done the bound check
    OFFSET_MASK_FLAG = 1 << 4 # Have I applied the offset mask

    MAY_NOT_OVERLOAD = (clang.CursorKind.BREAK_STMT,
            clang.CursorKind.CONTINUE_STMT, clang.CursorKind.GOTO_STMT,
            clang.CursorKind.LABEL_STMT, clang.CursorKind.INIT_LIST_EXPR)

    @classmethod
    def build_break_inst(cls, red=False):
        brk = Instruction()
        brk.kind = clang.CursorKind.BREAK_STMT
        if red:
            brk.set_modified()
        return brk

    def __init__(self):
        super().__init__()
        self.kind = None
        self.body  = None
        self.ignore = False
        # Mark which arguments are added to the code
        self.change_applied = 0
        # Mark if the instruction is generated by the tool or not
        self.color = InstructionColor.ORIGINAL
        # The last element of owner should be an object accesible from
        # local or global scope. The other elements would recursivly show the
        # fields in the object.
        self.owner = []
        # Link the instruction removed by the tool
        self.removed = []
        self.original = None

    def has_children(self):
        if self.kind not in Instruction.MAY_NOT_OVERLOAD:
            error('Function of base class (Instruction) is running for object of kind:', self.kind, 'has_children')
        if self.body is not None:
            return True
        return False

    def get_children(self):
        if self.kind not in Instruction.MAY_NOT_OVERLOAD:
            error('base get children is running for:', self.kind)
        if self.body is not None:
            return [self.body,]
        return []

    def get_children_context_marked(self):
        if self.kind not in Instruction.MAY_NOT_OVERLOAD:
            error('base get children context marked is running for:', self.kind)
        if self.body is not None:
            return [(self.body, BODY)]
        return []

    def clone(self, children):
        if self.kind not in Instruction.MAY_NOT_OVERLOAD:
            error('Instruction clone method uses parent implementation:', self.kind)
            debug('--', type(self), self.body)
        new = Instruction()
        new.kind = self.kind
        _default_clone_operation(new, self)
        if children:
            new.body = children[0]
        assert new.kind is not None
        return new

    def __str__(self):
        return f'<Inst {self.kind}>'

    def __repr__(self):
        return self.__str__()

    def set_modified(self, color=InstructionColor.RED):
        """
        Mark instruction as modified by the tool
        """
        assert color in INSTRUCTION_COLORS
        assert self.color == InstructionColor.ORIGINAL or self.color == color, f'we are overriding another red-color {self.color} --> {color}'
        self.color = color
        return self

    def is_modified(self):
        return self.color != InstructionColor.ORIGINAL

    def has_flag(self, flag):
        # assert flag in INSTRUCTION_FLAGS
        return self.change_applied & flag != 0

    def set_flag(self, flag, on=True):
        # assert flag in INSTRUCTION_FLAGS
        if on:
            self.change_applied |= flag
        else:
            self.change_applied &= ~flag



class Return(Instruction):
    @classmethod
    def build(cls, values, red=False):
        obj = Return()
        obj.body.extend_inst(values)
        if red:
            obj.set_modified()
        return obj

    def __init__(self):
        super().__init__()
        self.body = Block(ARG)
        self.kind = clang.CursorKind.RETURN_STMT

    def has_children(self):
        return self.body.has_children()

    def get_children(self):
        return [self.body,]

    def get_children_context_marked(self):
        return [(self.body, ARG),]

    def clone(self, children):
        new = Return()
        _default_clone_operation(new, self)
        new.body  = children[0]
        return new


class Call(Instruction):
    __slots__ = ('cursor', 'name', 'args', 'func_ptr', 'is_func_ptr',
            'is_operator', 'is_method', 'rd_buf', 'wr_buf', 'repeat')
    def __init__(self, cursor):
        super().__init__()
        self.cursor = cursor
        self.kind = clang.CursorKind.CALL_EXPR
        if cursor is None:
            self.name = '_not_set_'
        else:
            self.name = cursor.spelling
        self.func_ptr = None
        self.args = []
        self.is_func_ptr = False

        if self.name.startswith('operator'):
            self.is_operator = True
        else:
            self.is_operator = False

        if cursor is None:
            self.is_method = False
        else:
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
                assert len(self.owner) < 2

                if self.owner:
                    ref = self.owner[0]
                    ref_type = ref.type
                    while ref_type.kind == clang.TypeKind.TYPEDEF:
                        ref_type = ref_type.under_type
                    if ref_type.kind == clang.TypeKind.POINTER:
                        self.is_func_ptr = True
                        self.func_ptr = ref
                        self.owner = ref.owner

        self.rd_buf = None
        self.wr_buf = None
        self.repeat = None

    @property
    def spelling(self):
        """
        This is for backward compatibility with the clang Cursor object (Some
        old utility code which operate on cursors would also work on this
        object too)
        """
        return self.name

    def __str__(self):
        return f'<Call {self.name} ({self.args})>'

    def get_arguments(self):
        return list(self.args)

    def get_function_def(self):
        func = Function.directory.get(self.name)
        return func

    def has_children(self):
        return len(self.args) >  0

    def get_children(self):
        return self.args

    def get_children_context_marked(self):
        return list(zip(self.args, [ARG] * len(self.args)))

    def clone(self, children):
        new = Call(self.cursor)
        _default_clone_operation(new, self)
        new.name  = self.name
        new.args  = children
        new.is_func_ptr = self.is_func_ptr
        new.is_method = self.is_method
        new.is_operator = self.is_operator
        new.rd_buf = self.rd_buf
        new.wr_buf = self.wr_buf
        new.repeat = self.repeat
        return new

    @property
    def return_type(self):
        func = self.get_function_def()
        assert func is not None
        return func.return_type


class VarDecl(Instruction):
    __slots__ = ('cursor', 'type', 'name', 'init')
    @classmethod
    def build(cls, name, T, red=False):
        obj = VarDecl(None)
        obj.name = name
        obj.type = T
        if red:
            obj.set_modified()
        return obj

    def __init__(self, c):
        super().__init__()
        if c is not None:
            # TODO: get rid of cursor pointer.
            # TODO: this is because I am not following a solid design in
            # implementing things
            self.cursor = c
            self.type = MyType.from_cursor_type(c.type)
            self.name = c.spelling
        else:
            self.cursor = None
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
        if not self.has_children():
            return []
        return [self.init, ]

    def get_children_context_marked(self):
        if not self.has_children():
            return []
        return ((self.init, ARG),)

    def clone(self, children):
        new = VarDecl(self.cursor)
        _default_clone_operation(new, self)
        new.type = self.type
        new.name = self.name
        new.kind = self.kind
        if children:
            new.init = children[0]
        return new

    def get_ref(self):
        ref      = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        ref.name = self.name
        ref.type = self.type
        ref.original = self.original
        return ref

    def update_symbol_table(self, sym_tbl):
        return sym_tbl.insert_entry(self.name, self.type, self.kind, None)


class ControlFlowInst(Instruction):
    __slots__ = ('cond', 'other_body', 'repeat', 'likelihood')

    @classmethod
    def build_switch(cls, cond, red=False):
        switch = ControlFlowInst()
        switch.kind = clang.CursorKind.SWITCH_STMT
        switch.cond.add_inst(cond)
        if red:
            switch.set_modified()
        return switch


    @classmethod
    def build_if_inst(cls, condition_inst, red=False):
        obj = ControlFlowInst()
        obj.kind = clang.CursorKind.IF_STMT
        obj.cond.add_inst(condition_inst)
        if red:
            obj.set_modified()
        return obj

    def __init__(self):
        super().__init__()
        self.kind = None
        self.cond = Block(ARG)
        self.body = Block(BODY)
        self.other_body = Block(BODY)
        self.repeat = None
        self.likelihood = Likelihood.Neutral

    def has_children(self):
        return True

    def __str__(self):
        return f'<CtrlFlow {self.kind}: {self.cond}>'

    def get_children(self):
        if not self.other_body.has_children():
            return [self.cond, self.body]
        return [self.cond, self.body, self.other_body]

    def get_children_context_marked(self):
        groups = self.get_children()
        return _generate_marked_children(groups)

    def clone(self, children):
        new = ControlFlowInst()
        _default_clone_operation(new, self)
        new.kind = self.kind
        new.cond = children[0]
        new.body = children[1]
        if len(children) > 2:
            new.other_body = children[2]
        new.repeat = self.repeat
        new.likelihood = self.likelihood
        return new


class UnaryOp(Instruction):
    __slots__ = ('child', 'cursor', 'comes_after', 'op')

    BIT_OPS = ('~')
    BOOL_OPS =  ('!',)
    ARITH_OPS = ('-', '++', '--',)
    ADDR_OPS = ('&', '*',)
    OPS = ('~', '!', '-', '++', '--', '&', '*', 'sizeof', '__extension__', )

    @classmethod
    def build(cls, op, inst, red=False):
        assert op in UnaryOp.OPS
        obj = UnaryOp(None)
        obj.op = op
        obj.child.add_inst(inst)
        if red:
            obj.set_modified()
        return obj

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

    @property
    def operand(self):
        return self.child.children[0]

    @property
    def type(self):
        T = self.child.children[0].type
        if self.op == '&':
            return MyType.make_pointer(T)
        elif self.op == '*':
            assert T.is_pointer(), 'derefrencing a non pointer type!'
            return T.get_pointee()
        elif self.op == 'sizeof':
            return BASE_TYPES[clang.TypeKind.ULONGLONG]
        else:
            return T

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
        groups = [self.child]
        return _generate_marked_children(groups)

    def clone(self, children):
        """
        Clone the Unary Operator instruction
        @param children: list of cloned children (This functio will not clone the children it self)
        @returns a new UnaryOp object with representing the same instruction is this object.
        """
        new = UnaryOp(self.cursor)
        _default_clone_operation(new, self)
        new.op = self.op
        new.child = children[0]
        new.comes_after = self.comes_after
        return new


class BinOp(Instruction):
    __slots__ = ('lhs', 'rhs', 'op')

    REL_OP = ('>', '>=', '<', '<=', '==', '!=')
    ARITH_OP = ('+', '-', '*', '/', '%')
    ASSIGN_OP = ('=', '+=', '-=', '*=', '/=', '<<=', '>>=', '&=', '|=')
    BIT_OP = ('&', '|', '<<', '>>')
    LOGICAL_OP = ('&&', '||')
    ALL_OP = tuple(itertools.chain(REL_OP, ARITH_OP, ASSIGN_OP, BIT_OP, LOGICAL_OP))

    OPEN_GROUP = '({['
    CLOSE_GROUP = ')}]'

    @classmethod
    def build(cls, lhs_inst, op, rhs_inst, red=False):
        assert op in BinOp.ALL_OP, f'Unexpected binary operation requseted ({op})'
        obj = BinOp(None)
        obj.lhs.add_inst(lhs_inst)
        obj.op = op
        obj.rhs.add_inst(rhs_inst)
        if red:
            obj.set_modified()
        return obj

    def __init__(self, cursor):
        super().__init__()

        self.kind = clang.CursorKind.BINARY_OPERATOR
        self.lhs = Block(LHS)
        self.rhs = Block(RHS)
        self.op = ''

        if cursor is not None:
            accepted_kind = (clang.CursorKind.BINARY_OPERATOR,
                    clang.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR)
            assert cursor.kind in accepted_kind, f'wrong cursor kind {cursor.kind}'
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
        assert self.op in BinOp.ALL_OP, f'Unexpected binary operation requseted ({self.op})'

    @property
    def type(self):
        if self.op in (BinOp.REL_OP + BinOp.LOGICAL_OP):
            # Boolean result
            return BASE_TYPES[clang.TypeKind.UCHAR]
        else:
            # Otherwise what ever is the type of first operand
            T = self.lhs.children[0].type
            return T

    def has_children(self):
        return True

    def get_children(self):
        return [self.rhs, self.lhs]

    def get_children_context_marked(self):
        groups = (self.rhs, self.lhs)
        return _generate_marked_children(groups)

    def clone(self, children):
        new = BinOp(None)
        _default_clone_operation(new, self)
        new.op = self.op
        assert isinstance(children[0], Block)
        new.rhs = children[0]
        new.lhs = children[1]
        return new


class CaseSTMT(Instruction):
    __slots__ = ('cursor', 'case')

    def __init__(self, cursor, kind=clang.CursorKind.CASE_STMT):
        super().__init__()
        self.kind = kind
        self.cursor = cursor
        self.case = Block(ARG)
        self.body = Block(BODY)

    def has_children(self):
        return True

    def get_children(self):
        return [self.case, self.body]

    def get_children_context_marked(self):
        groups = (self.case, self.body)
        return _generate_marked_children(groups)

    def clone(self, children):
        new = CaseSTMT(self.cursor, self.kind)
        _default_clone_operation(new, self)
        new.case = children[0]
        new.body = children[1]
        return new


class ArrayAccess(Instruction):
    __slots__ = ('array_ref', 'type', 'index')

    @classmethod
    def build(cls, ref, index, red=False):
        obj = ArrayAccess(ref.type)
        obj.array_ref = ref
        assert isinstance(index, Instruction)
        obj.index.add_inst(index)
        if red:
            obj.set_modified()
        return obj

    def __init__(self, T):
        super().__init__()
        self.kind = clang.CursorKind.ARRAY_SUBSCRIPT_EXPR
        self.type = T
        self.array_ref = None
        self.index = Block(ARG)

    @property
    def name(self):
        if isinstance(self.array_ref, Ref):
            return self.array_ref.name
        return None

    # @property
    # def owner(self):
    #     return self.array_ref.owner

    def has_children(self):
        return True

    def get_children(self):
        return [self.array_ref, self.index]

    def get_children_context_marked(self):
        context = (None, ARG)
        groups = (self.array_ref, self.index)
        return ((self.array_ref, None), (self.index, ARG),)

    def clone(self, children):
        new = ArrayAccess(self.type)
        _default_clone_operation(new, self)
        new.array_ref = children[0]
        new.index = children[1]
        return new

    def __str__(self):
        return f'<ArrayAccess {self.name}@{self.index.children}>'


class Parenthesis(Instruction):
    @classmethod
    def build(cls, inst, red=False):
        obj = Parenthesis()
        obj.body.add_inst(inst)
        if red:
            obj.set_modified()
        return obj

    def __init__(self):
        super().__init__()
        self.kind = clang.CursorKind.PAREN_EXPR
        self.body = Block(ARG)

    @property
    def type(self):
        assert len(self.body.children) == 1
        inner_inst = self.body.children[0]
        return inner_inst.type

    def has_children(self):
        return True

    def get_children(self):
        return [self.body,]

    def get_children_context_marked(self):
        return ((self.body, self.body.tag),)

    def clone(self, children):
        new = Parenthesis()
        _default_clone_operation(new, self)
        new.body = children[0]
        return new


class Cast(Instruction):
    __slots__ = ('castee', 'type')

    @classmethod
    def build(cls, inst, T, red=False):
        obj = Cast()
        obj.castee.add_inst(inst)
        obj.type = T
        if red:
            obj.set_modified()
        return obj

    def __init__(self):
        super().__init__()
        self.kind = clang.CursorKind.CSTYLE_CAST_EXPR
        self.castee = Block(ARG)
        self.type = None

    def has_children(self):
        return True

    def get_children(self):
        return [self.castee,]

    def get_children_context_marked(self):
        return ((self.castee, self.castee.tag),)

    def clone(self, children):
        new = Cast()
        _default_clone_operation(new, self)
        new.type = self.type
        new.castee = children[0]
        return new


class Ref(Instruction):
    __slots__ = ('cursor', 'name', 'type')

    def is_shared(self, info):
        sym, scope = info.sym_tbl.lookup2(self.name)
        if scope == info.sym_tbl.shared_scope:
            return True
        return False

    @classmethod
    def from_sym(cls, sym):
        ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        ref.name = sym.name
        ref.type = sym.type
        return ref

    @classmethod
    def build(cls, name, T, is_member=False, red=False):
        kind = clang.CursorKind.MEMBER_REF_EXPR if is_member else clang.CursorKind.DECL_REF_EXPR
        obj = Ref(None, kind)
        obj.name = name
        obj.type = T
        if red:
            obj.set_modified()
        return obj

    def __init__(self, cursor, kind=None):
        super().__init__()
        self.cursor = cursor
        if cursor is None:
            self.name = '<unnamed>'
            self.kind = kind
            self.type = None
        else:
            self.name = cursor.spelling
            self.kind = cursor.kind if kind is None else kind
            self.owner = get_owner(self.cursor)
            assert len(self.owner) < 2
            self.type = MyType.from_cursor_type(cursor.type)

    def __str__(self):
        return f'<Ref {self.name}>'

    def is_func_ptr(self):
        return self.type.is_func_ptr()

    def is_member(self):
        return self.kind == clang.CursorKind.MEMBER_REF_EXPR

    def has_children(self):
        return False

    def get_children(self):
        return []

    def get_children_context_marked(self):
        return []

    def clone(self, _):
        new = Ref(self.cursor, self.kind)
        _default_clone_operation(new, self)
        new.name  = self.name
        new.type  = self.type
        return new

    def get_ref_field(self, name, info):
        assert info is not None
        ref = Ref(None, clang.CursorKind.MEMBER_REF_EXPR)
        ref.name = name
        T = self.type
        T = get_actual_type(T)
        key = f'class_{T.spelling}'
        if key not in info.sym_tbl.scope_mapping:
            error(info.sym_tbl.scope_mapping)
            raise Exception(f'we do not know about the declaration of record: {key}')
        struct_scope = info.sym_tbl.scope_mapping[key]
        sym = struct_scope.lookup(name)
        if sym is None:
            error('Failed to find the field in the struct! field name:', name)
            debug('debug info:')
            debug(struct_scope.symbols)
            debug('-------------------')
            raise Exception('Failed to find the field in the struct!')
        ref.type = sym.type
        ref.owner.append(self)
        assert len(ref.owner) == 1, f'unexpected length {len(ref.owner)}'
        return ref


class Literal(Instruction):
    __slots__ = ('text',)
    def __init__(self, text, kind):
        super().__init__()
        self.kind = kind
        self.text = text

    @property
    def type(self):
        if self.kind == clang.CursorKind.INTEGER_LITERAL:
            return BASE_TYPES[clang.TypeKind.INT]
        elif self.kind == clang.CursorKind.STRING_LITERAL:
            return MyType.make_pointer(BASE_TYPES[clang.TypeKind.UCHAR])
        elif self.kind == clang.CursorKind.CHARACTER_LITERAL:
            return BASE_TYPES[clang.TypeKind.SCHAR]
        else:
            debug('Trying to guess the type for', self, self.kind)
            error('I do not know the type')
            # raise Exception('I do not know the type')
            return None

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
        _default_clone_operation(new, self)
        new.text = self.text
        return new

class ForLoop(Instruction):
    __slots__ = ('cursor', 'pre', 'cond', 'post', 'repeat')

    @classmethod
    def build(cls, pre, cond, post, red=False):
        obj = ForLoop()
        obj.pre.add_inst(pre)
        obj.cond.add_inst(cond)
        obj.post.add_inst(post)
        if red:
            obj.set_modified()
        return obj

    def __init__(self):
        super().__init__()
        self.cursor = None
        self.kind = clang.CursorKind.FOR_STMT
        self.pre = Block(ARG)
        self.cond = Block(ARG)
        self.post = Block(ARG)
        self.body = Block(BODY)
        self.repeat = None

    def has_children(self):
        return True

    def get_children(self):
        return [self.pre, self.cond, self.post, self.body]

    def get_children_context_marked(self):
        groups = (self.pre, self.cond, self.post, self.body)
        return _generate_marked_children(groups)

    def clone(self, children):
        new = ForLoop()
        _default_clone_operation(new, self)
        new.cursor = self.cursor
        new.pre = children[0]
        new.cond = children[1]
        new.post = children[2]
        new.body = children[3]
        new.repeat = self.repeat
        return new


class Block(Instruction):
    __slots__ = ('tag', 'children')

    def __init__(self, tag):
        super().__init__()
        self.kind = BLOCK_OF_CODE
        self.tag = tag
        self.children = []

    def __str__(self):
        return f'<Block>'

    def add_inst(self, inst):
        assert isinstance(inst, Instruction)
        self.children.append(inst)

    def extend_inst(self, insts):
        for inst in insts:
            assert isinstance(inst, Instruction)
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
        _default_clone_operation(new, self)
        new.children = children[0]
        return new

    def __contains__(self, other):
        d = DFSPass(self, inside=True)
        for inst, _ in d:
            if inst == other:
                return True
            d.go_deep()
        return False


class ToUserspace(Instruction):
    __slots__ = ('current_func', 'path_id')

    @classmethod
    def from_func_obj(cls, func):
        assert isinstance(func, (Function, type(None)))
        obj = ToUserspace()
        obj.current_func = func
        return obj
    
    def __init__(self):
        super().__init__()
        self.kind = TO_USERSPACE_INST
        self.current_func = None
        self.path_id = 1

    @property
    def is_bpf_main(self):
        return self.current_func is None

    @property
    def return_type(self):
        if self.current_func is None:
            # Assume on the main function
            return BASE_TYPES[clang.TypeKind.INT]
        return self.current_func.return_type

    def __str__(self):
        return f'<ToUserspace>'

    def clone(self, _):
        new = ToUserspace()
        _default_clone_operation(new, self)
        new.current_func = self.current_func
        new.path_id = self.path_id
        return new

    def has_children(self):
        return False

    def get_children(self):
        return []

    def get_children_context_marked(self):
        return []


class Annotation(Instruction):
    __slots__ = ('msg', 'ann_kind', 'block')

    ANNOTATION_TYPE_NAME = 'struct __annotation'
    MESSAGE_FIELD_NAME = 'message'
    KIND_FIELD_NAME = 'kind'

    FUNC_PTR_DELIMITER = '-->'

    ANN_SKIP          = 'ANN_SKIP'
    ANN_FUNC_PTR      = 'ANN_FUNC_PTR'
    ANN_CACNE_DEFINE  = 'ANN_CACNE_DEFINE'
    ANN_CACHE_BEGIN   = 'ANN_CACHE_BEGIN'
    ANN_CACHE_END     = 'ANN_CACHE_END'
    ANN_EXCLUDE_BEGIN = 'ANN_EXCLUDE_BEGIN'
    ANN_EXCLUDE_END   = 'ANN_EXCLUDE_END'

    ANN_CACHE_BEGIN_UPDATE = 'ANN_CACHE_BEGIN_UPDATE'
    ANN_CACHE_END_UPDATE   = 'ANN_CACHE_END_UPDATE'

    ANN_LOOP          = 'ANN_LOOP'
    ANN_IGNORE_INST   = 'ANN_IGNORE_INST'

    def __init__(self, msg, ann_kind):
        super().__init__()
        assert len(msg) > 2
        assert ann_kind in (Annotation.ANN_SKIP, Annotation.ANN_FUNC_PTR,
                Annotation.ANN_CACNE_DEFINE, Annotation.ANN_CACHE_BEGIN,
                Annotation.ANN_CACHE_END, Annotation.ANN_EXCLUDE_BEGIN,
                Annotation.ANN_EXCLUDE_END, Annotation.ANN_CACHE_BEGIN_UPDATE,
                Annotation.ANN_CACHE_END_UPDATE, Annotation.ANN_LOOP,
                Annotation.ANN_IGNORE_INST,)
        # self.msg = msg[1:-1]
        self.msg = eval(msg)
        self.ann_kind = ann_kind
        self.kind = ANNOTATION_INST
        # TODO: rename block to body
        self.block = Block(BODY)

    def is_block_annotation(self):
        return self.ann_kind in (Annotation.ANN_CACHE_BEGIN,)

    def end_block_ann_kind(self):
        if not self.is_block_annotation():
            return None
        m = {
                Annotation.ANN_CACHE_BEGIN: Annotation.ANN_CACHE_END,
                Annotation.ANN_CACHE_BEGIN_UPDATE: Annotation.ANN_CACHE_END_UPDATE,
                }
        return m[self.ann_kind]

    def __str__(self):
        return f'<Annotation `{self.ann_kind}\' >'

    def clone(self, list_child):
        # TODO: Do not need to clone :) ?! (it is goofy)
        new = Annotation('"xxx"', self.ann_kind)
        _default_clone_operation(new, self)
        new.msg = self.msg
        new.block = list_child[0]
        return new

    def has_children(self):
        return self.block.has_children()

    def get_children(self):
        return [self.block, ]

    def get_children_context_marked(self):
        return [(self.block, self.block.tag), ]

# TODO: The implementation of this class is not complete yet.
# Idea: also add a class to represent field assignments. Then the body of
# Initialization class would be a list of field assignments. A field assignment
# is basically a name of a field and the value for the assignment.
class Initialization(Instruction):
    __slots__ = tuple()

    def __init__(self):
        super().__init__()
        self.body = []
        self.kind = clang.CursorKind.INIT_LIST_EXPR

    def has_children(self):
        return False
        # return len(self.body) > 0

    def get_children(self):
        return []
        # return self.body[:]

    def get_children_context_marked(self):
        return []
        # tmp = [(c, RHS) for c in self.body]
        # return tmp

    def clone(self, children):
        new = Initialization()
        _default_clone_operation(new, self)
        new.body = children
        return new
