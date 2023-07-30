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
        from user import UserProg
        self.entry_func_name = None
        self.rd_buf = PacketBuffer(None)
        self.wr_buf = PacketBuffer(None)
        self.prog = SK_SKB_PROG()
        self.sym_tbl = SymbolTable()
        # Keep track of global variables that where actually accessed. This
        # helps with generating the BPF map shared across connections.
        self.global_accessed_variables = set()

        # Keep track of information about the userspace program
        self.user_prog = UserProg()

        # TODO: the use of this set is very limited maybe I could do something
        # better
        self.remove_cursor = set()

        # TODO: this has not been used yet! what I was thinking and why I added this?
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
        if cursor is None:
            self.cursor = None
            self.name = '__not_set_to_a_name__'
        else:
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

    def set(self, name, value):
        """
        Set the value of `name', but does not change the state of stack.
        """
        self.code_block_reference[name] = value

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
            self.type_ref = MyType.from_cursor_type(c.type)
        else:
            self.cursor = None
            self.name = None
            self.type = None
            self.kind = None
            self.is_pointer = False
            self.type_ref = None

    def clone(self):
        new = StateObject(self.cursor)
        new.name = self.name
        new.type = self.type
        new.kind = self.kind
        new.type_ref = self.type_ref
        return new

    def get(self, name):
        if self.type_ref:
            for f in self.type_ref.fields:
                if f.name == name:
                    return f

    def get_c_code(self):
        T = self.type_ref
        if T.is_array():
            el_count = T.element_count
            # The following lines of code is for handling the multi-dimensional arrays.
            sub_T = T.element_type
            if sub_T.is_array():
                sub_var = StateObject(None)
                sub_var.type_ref = self.type_ref.element_type
                sub_var.type = sub_var.type_ref.spelling
                sub_var.name = self.name
                tmp = sub_var.get_c_code() # recursion
                assert tmp[-1] == ';'
                tmp = tmp[:-1] # drop the semi-colon

                first_brack = tmp.find('[')
                # insert the array dimension before the current existing ones
                text = f'{tmp[:first_brack]}[{el_count}]{tmp[first_brack:]};'
            else:
                text = f'{sub_T.spelling} {self.name}[{el_count}];'

            return text
        elif self.type_ref.kind == clang.TypeKind.RECORD:
            return f'struct {self.type} {self.name};'
        return f'{self.type} {self.name};'

    def __repr__(self):
        return f'<StateObject: {self.type} {self.name}>'


class MyType:
    @classmethod
    def make_array(cls, name, T, count):
        obj = MyType()
        obj.spelling = name
        obj.under_type = T
        obj._element_count = count
        obj.kind = clang.TypeKind.CONSTANTARRAY
        return obj

    @classmethod
    def make_pointer(cls, T):
        obj = MyType()
        obj.spelling = f'{T.spelling} *'
        obj.under_type = T
        obj.kind = clang.TypeKind.POINTER
        return obj

    @classmethod
    def make_simple(cls, name, kind):
        obj = MyType()
        obj.spelling = name
        obj.kind = kind
        return obj

    @classmethod
    def from_cursor_type(cls, T):
        obj = MyType()
        obj.spelling = T.spelling
        obj.kind = T.kind
        if obj.is_pointer():
            obj.under_type = MyType.from_cursor_type(T.get_pointee())
        elif obj.is_array():
            obj.under_type = MyType.from_cursor_type(T.element_type)
            obj._element_count = T.element_count
        return obj

    def __init__(self):
        self.spelling = None
        self.under_type = None
        self.kind = None
        self._element_count = 0

    def get_pointee(self):
        if self.kind == clang.TypeKind.POINTER:
            return self.under_type
        raise Exception('Not a pointer')

    @property
    def element_type(self):
        assert self.kind == clang.TypeKind.CONSTANTARRAY
        assert self.under_type is not None
        return self.under_type

    @property
    def element_count(self):
        assert self.kind == clang.TypeKind.CONSTANTARRAY
        return self._element_count

    def is_array(self):
        return self.kind == clang.TypeKind.CONSTANTARRAY

    def is_pointer(self):
        return self.kind == clang.TypeKind.POINTER

    def is_record(self):
        return self.kind == clang.TypeKind.RECORD

    def clone(self):
        obj = MyType()
        obj.spelling = self.spelling
        if self.under_type is not None:
            obj.under_type = self.under_type.clone()
        obj.kind = self.kind
        obj._element_count = self._element_count
        return obj


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

    # TODO: I need to seperate the directory for BPF and Userspace program
    directory = {}
    def __init__(self, name, c, directory=None):
        # TODO: what to do about this dependency??
        from instruction import Block, BODY
        super().__init__(name)

        # self.cursor = c
        if c is not None:
            self.args = [StateObject(a) for a in c.get_arguments()]
            self.return_type = MyType.from_cursor_type(c.result_type)
        else:
            self.args = []
            self.return_type = None

        self.body = Block(BODY)
        self.is_method = False
        self.may_have_context_ptr = False
        self.may_fail = False
        self.may_succeed = False

        self.path_ids = []

        if directory is None:
            directory = Function.directory
        if self.name in directory:
            debug(directory)
            raise Exception(f'Function is already defined ({self.name})')
        directory[self.name] = self

    def clone(self, directory):
        return self.clone2(self.name, directory)

    def clone2(self, name, directory):
        f = Function(name, None, directory)
        for k, v in vars(self).items():
            if isinstance(v, list):
                # clone the list
                v = v[:]
            setattr(f, k, v)
        f.name = name
        return f

    def get_c_code(self):
        # raise Exception('Not implemented')
        return f'// [[ definition of function {self.name} ]]'

    def is_empty(self):
        return not self.body.has_children()


BASE_TYPES = {}
def prepare_base_types():
    kind_name_map = {
            clang.TypeKind.SCHAR: 'char',
            clang.TypeKind.VOID: 'void',
            }

    for kind, name in kind_name_map.items():
        BASE_TYPES[kind] = MyType.make_simple(name, kind)

prepare_base_types()
