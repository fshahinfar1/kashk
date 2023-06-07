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

        self.processed = ProcessedBook()


class ProcessedBook:
    def __init__(self):
        self.book = {}

    def remember(self, key, name):
        if key not in self.book:
            self.book[key] = set()
        self.book[key].add(name)

    def check(self, key, name):
        if key in self.book:
            return name in self.book[key]
        return False


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
        self.spelling = None
        self.under_type = None
        self.kind = None

    def get_pointee(self):
        if self.kind == clang.TypeKind.POINTER:
            return self.under_type
        raise Exception('Not a pointer')


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

    def update_symbol_table(self, sym_tbl):
        struct_name = self.name
        T = MyType()
        T.spelling = f'struct {struct_name}'
        T.kind = clang.TypeKind.RECORD
        scope_key = f'class_{T.spelling}'
        sym_tbl.insert_entry(scope_key, T, clang.CursorKind.CLASS_DECL, None)
        with sym_tbl.new_scope() as scope:
            sym_tbl.scope_mapping[scope_key] = scope
            for f in self.fields:
                T = MyType()
                T.spelling = f.type
                if f.is_pointer:
                    T.kind = clang.TypeKind.POINTER
                    T.under_type = None
                else:
                    T.kind = f.kind
                sym_tbl.insert_entry(f.name, T, clang.CursorKind.FIELD_DECL, None)

    def __repr__(self):
        return f'<Record {self.name} >'


class Function(TypeDefinition):

    directory = {}
    def __init__(self, name, c):
        # TODO: what to do about this dependency??
        from instruction import Block, BODY
        super().__init__(name)

        self.cursor = c
        if c.is_definition():
            children = list(c.get_children())
            body = children[-1]
            while body.kind == clang.CursorKind.UNEXPOSED_STMT:
                body = next(body.get_children())
            assert (body.kind == clang.CursorKind.COMPOUND_STMT)
        else:
            body = None

        self.body_cursor = body
        self.body = Block(BODY)
        self.args = [StateObject(a) for a in c.get_arguments()]
        self.return_type = c.result_type.spelling
        self.is_method = False

        self.may_have_context_ptr = False
        self.may_fail = False
        self.may_succeed = False

        if self.name in Function.directory:
            raise Exception(f'Function is already defined ({self.name})')
        Function.directory[self.name] = self

    def get_c_code(self):
        # raise Exception('Not implemented')
        return f'// [[ definition of function {self.name} ]]'

