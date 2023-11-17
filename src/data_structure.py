from contextlib import contextmanager
import clang.cindex as clang

from utility import (get_code, get_owner, generate_struct_with_fields,
        report_on_cursor, indent, PRIMITIVE_TYPE_SIZE)
from log import error, debug
from sym_table import SymbolTable


class Info:
    """
    Represents the general understanding of the program
    """

    @classmethod
    def from_io_ctx(cls, io_ctx):
        from bpf import SK_SKB_PROG, XDP_PROG
        info = Info()
        if io_ctx.bpf_hook == 'sk_skb':
            info.prog = SK_SKB_PROG()
        elif io_ctx.bpf_hook == 'xdp':
            info.prog = XDP_PROG()
        else:
            raise Exception(f'Unknown BPF hook ({io_ctx.bpf_hook})')
        info.io_ctx = io_ctx
        return info

    def __init__(self):
        from user import UserProg
        self.prog = None
        self.sym_tbl = SymbolTable()
        # Keep track of information about the userspace program
        self.user_prog = UserProg()
        self.io_ctx = None
        # Maps defined in using annotation
        self.map_definitions = {}
        # For tracking name of read buffers in a scope (scope name --> set of var names)
        self.read_decl = {}


class PacketBuffer:
    """
    A buffer passed to the read/write functions
    """
    def __init__(self, cursor):
        if cursor is None:
            # self.cursor = None
            self.name = '__not_set_to_a_name__'
        else:
            # self.cursor = cursor
            self.name = cursor.spelling
        # Determines the size of buffer
        self.size_cursor = None
        self.ref = None
        self.size_ref = None


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
    __slots__ = ('cursor', 'name', 'kind', 'type_ref')
    def __init__(self, c):
        if c:
            self.cursor = c
            self.name = c.spelling
            self.kind = c.type.kind
            self.type_ref = MyType.from_cursor_type(c.type)
        else:
            self.cursor = None
            self.name = None
            self.kind = None
            self.type_ref = None

    # @property
    # def type(self):
    #     return self.type_ref.spelling

    @property
    def is_pointer(self):
        assert isinstance(self.type_ref, MyType)
        return self.type_ref.is_pointer()

    def clone(self):
        new = StateObject(self.cursor)
        new.name = self.name
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
            return f'{self.type_ref.spelling} {self.name};'
        return f'{self.type_ref.spelling} {self.name};'

    def __repr__(self):
        return f'<StateObject: {self.type_ref.spelling} {self.name}>'


class FunctionPrototypeType:
    def __init__(self):
        self.args = []
        self.ret = None

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
        assert isinstance(T, clang.Type)
        obj = MyType()
        obj.spelling = T.spelling
        obj.kind = T.kind
        if obj.is_pointer():
            obj.under_type = MyType.from_cursor_type(T.get_pointee())
        elif obj.is_array():
            obj.under_type = MyType.from_cursor_type(T.element_type)
            obj._element_count = T.element_count
        elif obj.is_func_proto():
            proto_obj = FunctionPrototypeType()
            proto_obj.args = [MyType.from_cursor_type(t) for t in T.argument_types()]
            proto_obj.ret = MyType.from_cursor_type(T.get_result())
            obj.func_proto_obj = proto_obj
        elif obj.kind == clang.TypeKind.TYPEDEF:
            # TODO: maybe I want to track the declaration of types and objects
            decl = T.get_declaration()
            if decl:
                obj.under_type = MyType.from_cursor_type(decl.underlying_typedef_type)
            else:
                error('Did not found the TYPEDEF underlying type')
                obj.under_type = None
        elif obj.kind == clang.TypeKind.ELABORATED:
            decl = T.get_declaration()
            if decl:
                # children = tuple(decl.get_children())
                # debug('Elaborated children:', children)
                # report_on_cursor(decl)
                # debug(decl.type.kind)
                # for c in children:
                #     report_on_cursor(c)
                # debug('--------------------------------')
                # assert len(children) == 1, 'This is what I expect'
                # obj.under_type = MyType.from_cursor_type(decl.type)
                new_obj = MyType.from_cursor_type(decl.type)
                # Let's get rid of ELABORATED
                return new_obj
            else:
                error('Did not found the ELABORATED type declartion')
                obj.under_type = None
        return obj

    def __init__(self):
        self.spelling = None
        self.under_type = None
        self.kind = None
        self._element_count = 0
        self.func_proto_obj = None

    def __str__(self):
        if self.is_pointer():
            return self.spelling
        return self.spelling

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

    @property
    def mem_size(self):
        """
        Return amount of memory this type requires
        """
        if self.is_pointer() or self.is_func_proto():
            return 8
        elif self.is_array():
            return self.element_count * self.element_type.mem_size
        elif self.is_record():
            # assume it is a packed struct (assume no padding is added)
            size = 0
            # TODO: I should consider having access to the type definition in
            # this object instead of a seperate object
            tmp_hack = self.spelling[len('struct '):]
            record = Record.directory.get(tmp_hack)
            if record is None:
                error(f'did not found declaration for struct {tmp_hack} (is it a type I do not track in the compiler?)')
                return 0
            # debug(Record.directory)
            assert record is not None, f'did not found declaration for {tmp_hack}'
            for field in record.fields:
                size += field.type_ref.mem_size
            return size
        elif self.is_enum():
            # sizeof(int)
            return 4
        elif self.kind in PRIMITIVE_TYPE_SIZE:
            return PRIMITIVE_TYPE_SIZE[self.kind]
        elif self.kind == clang.TypeKind.TYPEDEF:
            return self.under_type.mem_size
        else:
            raise Exception('Does not know the size (unhandled case)?', self.kind)

    def is_array(self):
        return self.kind == clang.TypeKind.CONSTANTARRAY

    def is_pointer(self):
        return self.kind == clang.TypeKind.POINTER

    def is_record(self):
        return self.kind == clang.TypeKind.RECORD

    def is_func_proto(self):
        return self.kind == clang.TypeKind.FUNCTIONPROTO

    def is_func_ptr(self):
        # In my opinion both of the following cases are function pointers and I do not want to distinguish them.
        # case 1:
        #   void (*cb2)(int);
        # case 2:
        #   typedef void(*callback)(int);
        #   callback cb;
        case1 = (self.is_pointer() and self.get_pointee().is_func_proto())
        case2 = self.is_func_proto()
        return case1 or case2

    def is_enum(self):
        return self.kind == clang.TypeKind.ENUM

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
        self.is_used_in_bpf_code = False

    def get_name(self):
        return self.name

    def __hash__(self):
        return self.name.__hash__()

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.name == other.name
        return False

    def get_c_code(self):
        raise Exception('Not implemented')

    def update_symbol_table(self, sym_tbl):
        return None


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
        return '\n'+ d + ';'

    def __repr__(self):
        return f'<Elaborate {self.name} >'


class Enum(TypeDefinition):
    directory = {}

    @classmethod
    def from_cursor(cls, cursor):
        # Get the known object
        name = cursor.spelling
        if name in Enum.directory:
            return Enum.directory[name]
        # Create a new object
        obj = Enum(cursor.spelling)
        for child in cursor.get_children():
            obj.values.append(child.spelling)
        return obj

    def __init__(self, name):
        super().__init__(name)
        self.kind = clang.CursorKind.ENUM_DECL
        self.values = []
        # assert self.name not in Enum.directory, f'Multiple object of Enum with the same name ({self.name})!'
        Enum.directory[self.name] = self

    def get_c_code(self):
        values = '\n'.join(f'{val},' for val in self.values)
        values = indent(values, 1)
        text = f'enum {self.name} {{\n{values}\n}};'
        return text

    def get_name(self):
        return f'enum {self.name}'

    def update_symbol_table(self, sym_tbl):
        T = MyType()
        T.spelling = self.get_name()
        T.kind = clang.TypeKind.ENUM
        scope_key = self.get_name()
        sym_tbl.insert_entry(scope_key, T, clang.CursorKind.ENUM_DECL, None)
        for v in self.values:
            sym_tbl.insert_entry(v, T, clang.CursorKind.ENUM_CONSTANT_DECL, None)


class Record(TypeDefinition):
    directory = {}

    def __init__(self, name, fields):
        super().__init__(name)
        self.fields = fields
        # if self.name in Record.directory:
        #     raise Exception('Unexpected error')
        Record.directory[self.name] = self

    def get_c_code(self):
        return generate_struct_with_fields(self.name, self.fields)

    def get_name(self):
        return f'struct {self.name}'

    def update_symbol_table(self, sym_tbl):
        struct_name = self.name
        T = MyType()
        T.spelling = self.get_name()
        T.kind = clang.TypeKind.RECORD
        scope_key = f'class_{T.spelling}'
        sym_tbl.insert_entry(scope_key, T, clang.CursorKind.CLASS_DECL, None)
        with sym_tbl.new_scope() as scope:
            sym_tbl.scope_mapping[scope_key] = scope
            for f in self.fields:
                T = MyType()
                T.spelling = f.type_ref.spelling
                if f.is_pointer:
                    T.kind = clang.TypeKind.POINTER
                    T.under_type = None
                else:
                    T.kind = f.kind
                sym_tbl.insert_entry(f.name, T, clang.CursorKind.FIELD_DECL, None)

    def __repr__(self):
        return f'<Record {self.name} >'


class FunctionBodyEvaluator:
    def __init__(self, body, info, f):
        """
        @param body --> cursor to the body of the function
        @param info --> info object
        @param f    --> function structure
        """
        self.info = info
        self.body = body
        self.f    = f

    def __call__(self):
        from instruction import Block, BODY
        from understand_logic import gather_instructions_under
        # Switch scope
        with self.info.sym_tbl.with_func_scope(self.f.name):
            # Process function body recursively
            body = gather_instructions_under(self.body, self.info, BODY)
            blk = Block(BODY)
            blk.children = body
            return blk


class Function(TypeDefinition):
    CTX_FLAG  = 1 << 0
    SEND_FLAG = 1 << 1
    FAIL_FLAG = 1 << 2

    func_cursor = {}
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

        self._body = Block(BODY)
        self.is_method = False
        self.is_operator = False
        self.may_have_context_ptr = False
        self.may_fail = False
        self.may_succeed = False
        self.calls_send = False
        self.calls_recv = False

        self.path_ids = []
        self.last_arg_is_auto_gen = False

        # What operations has alread been applied (bitset)
        self.change_applied = 0

        self.function_dependancy = set()

        if directory is None:
            directory = Function.directory
        if self.name in directory:
            raise Exception(f'Function is already defined ({self.name})')
        directory[self.name] = self

    @property
    def body(self):
        if callable(self._body):
            # Lazy evaluation of the body
            self._body = self._body()
        return self._body

    @body.setter
    def body(self, v):
        self._body  = v

    # def get_name(self):
    #     return f'func {self.name}'

    def clone(self, directory):
        return self.clone2(self.name, directory)

    def clone2(self, name, directory):
        f = Function(name, None, directory)
        for k, v in vars(self).items():
            if isinstance(v, list):
                # clone the list
                v = v[:]
            setattr(f, k, v)
        # Use the name passed to this function
        f.name = name
        return f

    def get_c_code(self):
        # raise Exception('Not implemented')
        return f'// [[ definition of function {self.name} ]]'

    def is_empty(self):
        if isinstance(self._body, FunctionBodyEvaluator):
            return False
        return not self._body.has_children()

    def get_arguments(self):
        return list(self.args)


BASE_TYPES = {}
def prepare_base_types():
    kind_name_map = {
            clang.TypeKind.SCHAR: 'char',
            clang.TypeKind.UCHAR: 'unsigned char',
            clang.TypeKind.VOID: 'void',
            clang.TypeKind.SHORT: 'short',
            clang.TypeKind.USHORT: 'unsigned short',
            clang.TypeKind.INT: 'int',
            clang.TypeKind.UINT: 'unsigned int',
            clang.TypeKind.LONG: 'long',
            clang.TypeKind.ULONG: 'unsigned long',
            clang.TypeKind.LONGLONG: 'long long',
            clang.TypeKind.ULONGLONG: 'unsigned long long',
            }

    for kind, name in kind_name_map.items():
        BASE_TYPES[kind] = MyType.make_simple(name, kind)

prepare_base_types()
