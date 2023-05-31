from contextlib import contextmanager
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


class StateObject:
    def __init__(self, c):
        if c:
            self.cursor = c
            self.name = c.spelling
            self.type = c.type.spelling
            self.kind = c.type.kind
            self.is_pointer = c.type.kind == clang.TypeKind.POINTER
            if self.is_pointer:
                self.real_type = c.type.get_pointee()
            else:
                self.real_type = c.type
        else:
            self.cursor = None
            self.name = None
            self.type = None
            self.kind = None
            self.is_pointer = False

        self.is_global = False
        self.type_ref = None
        self.parent_object = None


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


class MyType:
    def __init__(self):
        pass


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

    def __repr__(self):
        return f'<Elaborate {self.name} >'


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

    def __repr__(self):
        return f'<Record {self.name} >'


class Function(TypeDefinition):
    directory = {}
    def __init__(self, name, c):
        # TODO: what to do about this dependency??
        from instruction import Block, BODY
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
        self.body = Block(BODY)

        self.args = [StateObject(a) for a in c.get_arguments()]

        self.return_type = self.cursor.result_type.spelling

        self.is_method = False

        if self.name in Function.directory:
            raise Exception(f'Function is already defined ({self.name})')
        Function.directory[self.name] = self

    def get_c_code(self):
        # raise Exception('Not implemented')
        return f'// [[ definition of function {self.name} ]]'

