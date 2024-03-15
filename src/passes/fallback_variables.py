import clang.cindex as clang
from log import debug
from instruction import *
from data_structure import *
from passes.code_pass import Pass
from passes.clone import clone_pass
from sym_table import SymbolTable, Scope


MODULE_TAG = '[Fallback Vars]'


class FindFailureVariables(Pass):
    def __init__(self, info):
        super().__init__(info)
        self.vars = set()
        self.just_declare = set()
        # Local version of symbol table
        self.sym_tbl = SymbolTable()
        # Bring global symbols from the main symbol table
        self.sym_tbl.shared_scope.symbols = dict(info.sym_tbl.shared_scope.symbols.items())
        self.sym_tbl.global_scope.symbols = dict(info.sym_tbl.global_scope.symbols.items())
        # Create an empty event-loop scope
        self.sym_tbl.current_scope = Scope(self.sym_tbl.global_scope)

    def _handle_reference(self, inst, more):
        sym, scope = self.sym_tbl.lookup2(inst.name)
        if sym is None:
            # Unknown reference
            # Find the original symbol from the main table
            sym = self.info.sym_tbl.lookup(inst.name)
            # n = self.current_fname
            # debug(inst.name, '@', n)
            # debug(self.info.sym_tbl.current_scope.symbols)
            assert sym is not None, f'Unexpected, we did not found the symbol in the original table\n\t{inst}'
            parent = self.get_valid_parent()
            if (more.ctx == LHS and
                    parent.kind == clang.CursorKind.BINARY_OPERATOR and
                    parent.op == '='):
                # Writing to the variable
                # The old value should not be important
                debug(f'not caring about {sym.name}', tag=MODULE_TAG)
                self.just_declare.add(sym)
            else:
                self.vars.add(sym)
            self.sym_tbl.insert(sym)
            return inst
        else:
            # Known reference
            return inst
        return inst

    def _handle_failed_func_analysis(self, inst, more):
            func = inst.get_function_def()
            orig_func = func.based_on
            # Create the internal pass symbol table here so we can initialize it
            tbl = SymbolTable()
            tbl.shared_scope.symbols = dict(self.info.sym_tbl.shared_scope.symbols.items())
            tbl.global_scope.symbols = dict(self.info.sym_tbl.global_scope.symbols.items())
            gs = tbl.global_scope
            with tbl.with_scope(gs):
                func.update_symbol_table(tbl)
            tbl.current_scope = tbl.scope_mapping[func.name]
            tmp = FindFailureVariables.do(func.body, self.info,
                    func=orig_func, sym_tbl=tbl)
            # debug(func.name, tmp.vars, tag=MODULE_TAG)

            # prepend the do-not-care variable declarations
            tmp_decl = [VarDecl.build(v.name, v.type)
                    for v in tmp.just_declare]
            func.body.children = tmp_decl + func.body.children
            # add fallback vars to the function signiture
            tmp_new_args = [StateObject.build(v.name, v.type)
                    for v in tmp.vars]
            func.args.extend(tmp_new_args)

            func.fallback_vars = tmp.vars
            func.change_applied |= Function.FALLBACK_VAR

    def process_current_inst(self, inst, more):
        match inst.kind:
            case clang.CursorKind.DECL_REF_EXPR:
                return self._handle_reference(inst, more)
            case clang.CursorKind.MEMBER_REF_EXPR:
                # TODO: I do not need to copy all the struct, just the fields used.
                owner = inst.owner[-1]
                self.process_current_inst(owner, more)
                return inst
            case clang.CursorKind.VAR_DECL:
                sym = self.info.sym_tbl.lookup(inst.name)
                assert sym is not None, 'Unexpected!'
                self.sym_tbl.insert(sym)
                return inst
            case clang.CursorKind.CALL_EXPR:
                func = inst.get_function_def()
                if not func or func.is_empty():
                    return inst
                if func.based_on is None:
                    # This is an unmodified function, we do not need to check
                    # this.
                    return inst

                if func.change_applied & Function.FALLBACK_VAR == 0:
                    self._handle_failed_func_analysis(inst, more)

                if not inst.has_flag(Function.FALLBACK_VAR):
                    tmp_new_args = [Ref.build(v.name, v.type)
                            for v in func.fallback_vars]
                    inst.args.extend(tmp_new_args)
                    inst.set_flag(Function.FALLBACK_VAR)

                self.vars.update(func.fallback_vars)
                for sym in func.fallback_vars:
                    tmp_sym = self.sym_tbl.lookup(sym.name)
                    if tmp_sym is not None:
                        error('Variable name clash across multiple scopes, I need to rename stuff. It is something to be done :) for now just rename one of the variables.', tag=MODULE_TAG)
                        debug(sym.name, '@', self.current_fname, tag=MODULE_TAG)
                        # assert 0, 'Variable name clash across multiple scopes, I need to rename stuff. It is something to be done :) for now just rename one of the variables.'
                    self.sym_tbl.insert(sym)
        return inst


def failure_path_fallback_variables(info): 
    result = {}
    for pid, path in info.failure_paths.items():
        b = Block(BODY)
        b.children = path
        obj = FindFailureVariables.do(b, info)
        result[pid] = obj.vars
        # TODO: ? Declare variables at the begining of each path
        # for sym in self.vars:
        #     decl = VarDecl.build(sym.name, sym.type)
        #     insts.insert(0, decl)

    info.failure_vars = result
    for pid, fvars in result.items():
        debug('Path:', pid, fvars, tag=MODULE_TAG)

    # TODO: Create meta structures
