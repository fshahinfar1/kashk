import clang.cindex as clang
from contextlib import contextmanager
import pprint


class SymbolTableEntry:
    def __init__(self, name, type, kind, ref):
        self.name = name
        self.type = type
        self.kind = kind
        self.ref = ref

        self.is_pointer = type.kind == clang.TypeKind.POINTER

        # Optional
        self.value = None
        self.param_pos = 0
        self.is_bpf_ctx = False
        self.bpf_ctx_off = 0

    def __repr__(self):
        return f'"<{self.kind}  {self.name}: {self.type.spelling}>"'


class Scope:
    def __init__(self, parent=None):
        self.symbols = {}
        self.parent = parent

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
    def __init__(self):
        # State that is shared between connection
        self.shared_scope = Scope()
        # State which is maintained between packets of the same connection
        self.global_scope = Scope(self.shared_scope)
        self.current_scope = self.shared_scope
        # Expose the global/static scope maping table as part of this class
        self.scope_mapping = scope_mapping

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
        assert scope is not None
        cur = self.current_scope
        self.current_scope = scope
        try:
            yield None
        finally:
            self.current_scope = cur


class ScopeMapping:
    def __init__(self):
        self.scope_mapping = {}

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


scope_mapping = ScopeMapping()

