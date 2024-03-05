import clang.cindex as clang
from log import error, debug


PRIMITIVE_TYPE_SIZE = {
    clang.TypeKind.BOOL: 1,
    clang.TypeKind.CHAR_U: 1,
    clang.TypeKind.SCHAR: 1,
    clang.TypeKind.UCHAR: 1,
    clang.TypeKind.CHAR16: 2,
    clang.TypeKind.USHORT: 2,
    clang.TypeKind.SHORT: 2,
    clang.TypeKind.CHAR32: 4,
    clang.TypeKind.UINT: 4,
    clang.TypeKind.INT: 4,
    clang.TypeKind.ULONG: 8,
    clang.TypeKind.LONG: 8,
    clang.TypeKind.ULONGLONG: 8,
    clang.TypeKind.LONGLONG: 8,
    clang.TypeKind.UINT128: 16,
    clang.TypeKind.CHAR_S: 1,
    clang.TypeKind.WCHAR: 1,
    clang.TypeKind.INT128: 16,
    clang.TypeKind.FLOAT: 4,
    clang.TypeKind.DOUBLE: 8,
    clang.TypeKind.LONGDOUBLE: 16,
    clang.TypeKind.VOID: 0,
}


class FunctionPrototypeType:
    def __init__(self):
        self.args = []
        self.ret = None


class MyType:
    POINTER_SIZE = 8
    INT_SIZE = 4

    type_table = {}

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
        if obj.spelling.startswith('const'):
            # Remove the const keyword
            tmp = ' '.join(obj.spelling.split()[1:])
            obj.spelling = tmp
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
        if self.is_pointer() and self.under_type.is_array():
            tmp = '(*) {str(self.under_type)}'
            return tmp
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
        @returns int
        """
        if self.is_pointer() or self.is_func_proto():
            return MyType.POINTER_SIZE 
        elif self.is_array():
            return self.element_count * self.element_type.mem_size
        elif self.is_record():
            # assume it is a packed struct (assume no padding is added)
            size = 0
            # TODO: I should consider having access to the type definition in
            # this object instead of a seperate object
            tmp_hack = self.spelling[len('struct '):]
            record = MyType.type_table.get(tmp_hack)
            if record is None:
                debug(f'did not found declaration for struct {tmp_hack} (is it a type I do not track in the compiler?)')
                return 0
            # debug(Record.directory)
            assert record is not None, f'did not found declaration for {tmp_hack}'
            for field in record.fields:
                size += field.type_ref.mem_size
            return size
        elif self.is_enum():
            return MyType.INT_SIZE
        elif self.kind in PRIMITIVE_TYPE_SIZE:
            return PRIMITIVE_TYPE_SIZE[self.kind]
        elif self.kind == clang.TypeKind.TYPEDEF:
            return self.under_type.mem_size
        else:
            error('Does not know the size (unhandled case)?', self.kind)
            return 0

    def is_array(self):
        return self.kind == clang.TypeKind.CONSTANTARRAY

    def is_pointer(self):
        return self.kind == clang.TypeKind.POINTER

    def is_mem_ref(self):
        return self.is_array() or self.is_pointer()

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
