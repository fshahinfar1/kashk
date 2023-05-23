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

    def __repr__(self):
        return f'"<{self.kind}  {self.name}: {self.type.spelling}>"'


class Scope:
    def __init__(self, parent=None):
        self.symbols = {}
        self.parent = parent

    def insert(self, entry):
        self.symbols[entry.name] = entry

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
            return None

    def __repr__(self):
        return pprint.pformat(self.symbols)


class SymbolTable:
    def __init__(self):
        self.global_scope = Scope()
        self.current_scope = self.global_scope
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

    @contextmanager
    def new_scope(self):
        s = Scope(self.current_scope)
        self.current_scope = s
        try:
            yield s
        finally:
            self.current_scope = self.current_scope.parent


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

