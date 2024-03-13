import clang.cindex as clang
from contextlib import contextmanager
import pprint
from log import error, debug
from my_type import MyType


class SymbolAccessMode:
    NOT_ACCESSED = 0
    FIRST_WRITE = 1
    HAS_READ = 2


class MemoryRegion:
    BPF_CTX = 100
    STACK   = 200
    BPF_MAP = 300


class SymbolTableEntry:
    __slots__ = ('name', 'type', 'kind', 'ref', 'fields', 'is_bpf_ctx',
            'memory_region', 'referencing_memory_region')
    def __init__(self, name, type_, kind, ref, scope_holding_the_entry=None):
        self.name = name
        self.type = type_
        self.kind = kind
        self.ref = ref
        assert isinstance(type_, MyType)

        # This is added to handle the fields of a struct
        self.fields = Scope(scope_holding_the_entry)
        self.is_bpf_ctx = False

        # On what memory region is allocated
        self.memory_region = None
        # If it is pointer/array, to what memory region it is pointing
        self.referencing_memory_region = None

    def clone(self):
        e = SymbolTableEntry(self.name, self.type, self.kind, self.ref)
        #fields = vars(self).items()
        fields = tuple((k, self.__getattribute__(k)) for k in SymbolTableEntry.__slots__)
        for k, v in fields:
            setattr(e, k, v)
        # TODO: what should I pass as the parent of the cloned scope?
        e.fields = self.fields.clone(None)
        return e

    def __repr__(self):
        return f'"<{self.kind}  {self.name}: {self.type.spelling}>"'

    def set_mem_region(self, reg):
        self.memory_region = reg

    def set_ref_region(self, reg):
        assert self.type.is_pointer() or self.type.is_array()
        self.referencing_memory_region = reg

    def set_is_bpf_ctx(self, state):
        self.is_bpf_ctx = state


class Scope:
    __slots__ = ('number', 'symbols', 'parent', 'children')
    def __init__(self, parent=None):
        # TODO: the nubmer system is wrong and misleading. I should assign a
        # name to each scope. This way, the relation between scopes can easily
        # analysed, The scope_mapping could be generated better, The clone
        # scope know the original scope and can change their names if needed
        # afterward.
        self.number = 0 if parent is None else parent.number + len(parent.children) + 1
        self.symbols = {}
        self.parent = parent
        self.children = []
        if parent is not None:
            parent.add_child_scope(self)

    def clone(self, parent):
        # TODO: I only have considered cloning from the top of the tree
        assert parent is not None or self.parent is None
        clone_scope = Scope(parent)

        # Clone this scope's symbol table
        for key, entry in self.symbols.items():
            clone_entry = entry.clone()
            clone_scope.symbols[key] = clone_entry

        # Clone its children
        for child in self.children:
            scope = child.clone(clone_scope)

        return clone_scope

    def add_child_scope(self, child):
        self.children.append(child)

    def delete(self, name):
        return self.symbols.pop(name)

    def insert(self, entry):
        self.symbols[entry.name] = entry

    def insert_entry(self, name, type, kind, ref):
        e = SymbolTableEntry(name, type, kind, ref)
        self.insert(e)
        return e

    def lookup(self, name):
        entry = self.symbols.get(name)
        if entry:
            return entry
        elif self.parent:
            return self.parent.lookup(name)
        else:
            return None

    def lookup2(self, name):
        entry = self.symbols.get(name)
        if entry:
            return entry, self
        elif self.parent:
            return self.parent.lookup2(name)
        else:
            return None, None

    def __repr__(self):
        return pprint.pformat(self.symbols)


class SymbolTable:
    __slots__ = ('shared_scope', 'global_scope', 'current_scope', 'scope_mapping',)
    def __init__(self):
        # State that is shared between connection
        self.shared_scope = Scope()
        # State which is maintained between packets of the same connection
        self.global_scope = Scope(self.shared_scope)
        self.current_scope = self.shared_scope
        # Expose the global/static scope maping table as part of this class
        self.scope_mapping = ScopeMapping()

    def insert_entry(self, name, type, kind, ref):
        e = SymbolTableEntry(name, type, kind, ref)
        self.insert(e)
        return e

    def insert(self, entry):
        self.current_scope.insert(entry)

    def lookup(self, name):
        return self.current_scope.lookup(name)

    def lookup2(self, name):
        sym, scope = self.current_scope.lookup2(name)
        return sym, scope

    @contextmanager
    def new_scope(self):
        s = Scope(self.current_scope)
        self.current_scope = s
        try:
            yield s
        finally:
            self.current_scope = self.current_scope.parent

    @contextmanager
    def with_func_scope(self, func_name):
        scope = self.scope_mapping.get(func_name)
        assert scope is not None, f'Failed to find the scope for function {func_name}'
        cur = self.current_scope
        self.current_scope = scope
        try:
            yield scope
        finally:
            self.current_scope = cur

    @contextmanager
    def with_scope(self, scope):
        assert isinstance(scope, Scope)
        cur = self.current_scope
        self.current_scope = scope
        try:
            yield scope
        finally:
            self.current_scope = cur

    def clone(self):
        # Creat a new object
        new_tbl = SymbolTable()

        # Clone the top most scope
        new_tbl.shared_scope = self.shared_scope.clone(None)

        # Cloning the top most scope will clone every other scope connected to
        # it. I just need to find the coresponding references and set the
        # pointesr.

        shared_scp_num = self.shared_scope.number
        glb_scp_num = self.global_scope.number
        cur_scp_num = self.current_scope.number


        book = {}
        q = [new_tbl.shared_scope]
        while q:
            scp = q.pop()
            book[scp.number] = scp
            q.extend(reversed(scp.children))

        new_tbl.global_scope = book[glb_scp_num]

        # Clone the scope mapping
        for name, scope in self.scope_mapping.scope_mapping.items():
            scp_number = scope.number
            if scp_number not in book:
                debug('some scopes are not being cloned! scope:', scope)
                continue
            new_tbl.scope_mapping[name] = book[scp_number]

        return new_tbl


class ScopeMapping:
    __slots__ = ('scope_mapping',)
    def __init__(self):
        self.scope_mapping = {}

    def __contains__(self, item):
        return item in self.scope_mapping

    def __getitem__(self, key):
        return self.scope_mapping[key]

    def __setitem__(self, key, val):
        if key in self.scope_mapping:
            raise Exception(f'a scope with the same name is created? (name: {key})')
        self.scope_mapping[key] = val

    def __repr__(self):
        return pprint.pformat(self.scope_mapping)

    def get(self, key, default=None):
        return self.scope_mapping.get(key, default)
