import clang.cindex as clang
from contextlib import contextmanager
import pprint
from log import error, debug


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

    def clone(self):
        e = SymbolTableEntry(self.name, self.type, self.kind, self.ref)
        for k, v in vars(self).items():
            setattr(e, k, v)
        return e

    def __repr__(self):
        return f'"<{self.kind}  {self.name}: {self.type.spelling}>"'


class Scope:
    def __init__(self, parent=None):
        self.number = 0 if parent is None else parent.number + len(parent.children) + 1
        self.symbols = {}
        self.parent = parent
        self.children = []
        if parent is not None:
            parent.add_child_scope(self)

    def clone(self, parent):
        # TODO: I do not know how to clone from the midle of the tree
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
        assert scope is not None
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

        glb_scp_num = self.global_scope.number
        cur_scp_num = self.current_scope.number

        # if I found:  glb  | cur
        book = {}
        found =       [False, False]
        q = [new_tbl.shared_scope]
        while q:
            scp = q.pop()
            book[scp.number] = scp
            if scp.number == glb_scp_num:
                found[0] = True
                new_tbl.global_scope = scp
            if scp.number == cur_scp_num:
                found[1] = True
                new_tbl.current_scope = scp
            if all(found):
                break
            q.extend(reversed(scp.children))

        if not all(found):
            error('Failed to clone the scope')
            debug(found)
            debug(glb_scp_num, cur_scp_num)
            raise Exception('Failed to clone the scope')

        # Clone the scope mapping
        for name, scope in self.scope_mapping.scope_mapping.items():
            scp_number = scope.number
            new_tbl.scope_mapping[name] = book[scp_number]

        return new_tbl


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
