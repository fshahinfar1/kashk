class SymbolTableEntry:
    def __init__(self, name, type, scope, memory_location):
        self.name = name
        self.type = type
        self.scope = scope
        self.memory_location = memory_location
        self.value = None

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

class SymbolTable:
    def __init__(self):
        self.global_scope = Scope()
        self.current_scope = self.global_scope

    def insert(self, entry):
        self.current_scope.insert(entry)

    def lookup(self, name):
        return self.global_scope.lookup(name)

    def new_scope(self):
        s = Scope(self.current_scope)
        self.current_scope = s
        return s

    def free_scope(self):
        self.current_scope = self.current_scope.parent

# def traverse_ast(node, symbol_table):
#     if node.kind == clang.cindex.CursorKind.VAR_DECL:
#         # Variable Declaration
#         name = node.spelling
#         type = node.type.spelling
#         entry = SymbolTableEntry(name, type, 'variable', None)
#         symbol_table.insert(entry)

#     elif node.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
#         # Identifier Reference
#         name = node.spelling
#         symbol = symbol_table.lookup(name)
#         if symbol:
#             print("Identifier found in symbol table:", symbol.name)
#         else:
#             print("Identifier not found in symbol table:", name)

#     elif node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
#         # Function Definition
#         name = node.spelling
#         type = node.result_type.spelling
#         entry = SymbolTableEntry(name, type, 'function', None)
#         symbol_table.insert(entry)

#         # Create a new scope for the function
#         function_scope = Scope(symbol_table.current_scope)
#         symbol_table.current_scope = function_scope

#         # Process function parameters
#         for arg in node.get_arguments():
#             arg_name = arg.spelling
#             arg_type = arg.type.spelling
#             arg_entry = SymbolTableEntry(arg_name, arg_type, 'parameter', None)
#             symbol_table.insert(arg_entry)

#         # Process function body recursively
#         traverse_ast(node.get_children(), symbol_table)

#         # Restore the parent scope after function processing is done
#         symbol_table.current_scope = symbol_table.current_scope.parent

#     elif node.kind == clang.cindex.CursorKind.BINARY_OPERATOR:
#         # Binary Operator
#         operator = node.spelling
#         if operator == '=':
#             # Left-hand side of the assignment
#             lhs = node.get_children().next()
#             if lhs.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
#                 # Identifier being assigned a value
#                 name = lhs.spelling
#                 symbol = symbol_table.lookup(name)
#                 if symbol:
#                     # Right-hand side of the assignment
#                     rhs = node.get_children().next().get_children().next()
#                     if rhs.kind == clang.cindex.CursorKind.INTEGER_LITERAL:
#                         # Assigning an integer value
#                         value = rhs.spelling
#                         symbol.value = value
#                         print("Assigned value", value, "to variable", name)
#         else:
#             # Other binary operators (e.g., +, -, *, /)
#             lhs = node.get_children().next()
#             rhs = node.get_children().next().get_children().next()
#             if lhs.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
#                 # Left-hand side is an identifier
#                 lhs_name = lhs.spelling

