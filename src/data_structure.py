from contextlib import contextmanager
import clang.cindex as clang

from utility import (get_code, get_owner, generate_struct_with_fields, indent)
from log import error, debug
from sym_table import SymbolTable
from my_type import MyType


HASH_HELPER_HEADER = '#include "hash_fn.h"'
CSUM_HELPER_HEADER = '#include "csum_helper.h"'
XDP_HELPER_HEADER  = '#include "xdp_helper.h"'


class Info:
    """
    Represents the general understanding of the program
    """

    __slots__ = ('sym_tbl', 'prog', 'user_prog', 'io_ctx', 'map_definitions',
            'read_decl', 'func_cost_table', 'failure_paths',
            'failure_path_new_funcs', 'failure_vars')

    @classmethod
    def from_io_ctx(cls, io_ctx):
        info = Info()
        if io_ctx.bpf_hook == 'sk_skb':
            from bpf_hook.skskb import SK_SKB_PROG
            info.prog = SK_SKB_PROG()
        elif io_ctx.bpf_hook == 'xdp':
            from bpf_hook.xdp import XDP_PROG
            info.prog = XDP_PROG()
        else:
            raise Exception(f'Unknown BPF hook ({io_ctx.bpf_hook})')
        info.io_ctx = io_ctx
        return info

    def __init__(self):
        from user import UserProg
        self.sym_tbl = SymbolTable()
        self.prog = None
        # Keep track of information about the userspace program
        self.user_prog = UserProg()
        self.io_ctx = None
        # Maps defined in using annotation
        self.map_definitions = {}
        # For tracking name of read buffers in a scope (scope name --> set of var names)
        self.read_decl = {}
        self.func_cost_table = None
        self.failure_paths = None
        self.failure_path_new_funcs = None
        self.failure_vars = None


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

    def get2(self, name, at, default=None):
        assert isinstance(at, int) and at >= 0
        if at == 0:
            return self.get(name)
        count = 1
        for x in self.stack:
            if x[0] == name:
                count += 1
                if count > at:
                    # Found the result
                    return x[1]
        return None

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
    @classmethod
    def build(cls, name, T):
        obj = StateObject(None)
        obj.name = name
        obj.type_ref = T
        obj.kind = T.kind
        return obj

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

    @property
    def type(self):
        return self.type_ref

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
    def __init__(self, name, fields):
        super().__init__(name)
        self.fields = fields
        if self.name in MyType.type_table:
            debug('Multiple record object with the same name', self.name)
            # raise Exception('Unexpected error')
        MyType.type_table[self.name] = self

    @property
    def type(self):
        return MyType.make_simple(self.get_name(), clang.TypeKind.RECORD)

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
        from parser.understand_logic import gather_instructions_under
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
    FALLBACK_VAR = 1 << 5

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
        self.may_return_bpf_ctx_ptr = False
        self.calls_send = False
        self.calls_recv = False
        self.complexity = 0
        self.based_on = None
        self.fallback_vars = None

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

        self.attributes = 'static inline'

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

    def update_symbol_table(self, sym_tbl):
        scope_key = self.name
        if scope_key in sym_tbl.scope_mapping:
            debug('The function scope alread exists!')
        T = self.return_type
        sym_tbl.insert_entry(scope_key, T, clang.CursorKind.FUNCTION_DECL, None)
        with sym_tbl.new_scope() as scope:
            sym_tbl.scope_mapping[scope_key] = scope
            e = sym_tbl.insert_entry('__func__', T, clang.CursorKind.FUNCTION_DECL, None)
            e.name = self.name
            # Add function parameters to the scope
            for arg in self.args:
                e = sym_tbl.insert_entry(arg.name, arg.type_ref, clang.CursorKind.PARM_DECL, None)


VOID_PTR = 999
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
    BASE_TYPES[VOID_PTR] = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])


prepare_base_types()
