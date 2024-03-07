import clang.cindex as clang
from code_pass import Pass
from sym_table import SymbolTable
from memory.memory import Memory
from memory.mem_entry import MemEntry
from helpers.sym_tbl_helper import get_symbol


def _prepare_symbol_for_bound_checking(inst, sym):
    ref = Ref.from_sym(sym)



class Verifier(Pass):
    def __init__(self, info):
        super().__init__(info)
        # Prepare a local version of symbol table
        self.sym_tbl = SymbolTable()
        s = self.sym_tbl.new_scope(self.sym_tbl.global_scope) 
        self.sym_tbl.current_scope = s
        # Prepare a local view of memory layout
        self.memory  = Memory()
        self.sym_tbl.memory = self.memory

    def _handle_var_decl(self, inst, more):
        # Define a new variable on the stack
        T = inst.type
        mem = self.memory.alloc(MemEntry.REGION_STK, T)
        sym = self.sym_tbl.insert_entry(inst.name, T,
                clang.CursorKind.VAR_DECL, None)
        sym.mem_entry_ref = mem
        mem.associated_sym = sym
        if T.is_record():
            # Change the current scope to the fields of the record
            with self.sym_tbl.with_scope(sym.fields):
                record = T.get_record_def()
                for field in record.fields:
                    self._handle_var_decl(field, None)
        elif T.is_array():
            # array can hold multiple objects :)
            mem.val = []
            pass

        if inst.init.has_children() and T.is_pointer():
            lhs = inst.get_ref()
            rhs = inst.init.children[0]
            self._track_value(lhs, rhs)

    def _track_value(self, lhs, rhs):
        l_tmp = get_symbol(lhs)
        r_tmp = get_symbol(rhs)
        if l_tmp is None or r_tmp is None:
            return
        l_sym = l_tmp[-1]
        r_sym = r_tmp[-1]
        l_T = l_sym.type
        if not l_T.is_pointer() and not l_T.is_array():
            return 
        l_mem = l_sym.mem_entry_ref
        r_mem = r_sym.mem_entry_ref
        l_mem.val = r_mem.val

    def _handle_binop(self, inst, more):
        lhs = inst.lhs.children[0]
        rhs = inst.rhs.children[0]

        for x in [lhs, rhs]:
            tmp = get_symbol(x)
            if tmp is None:
                continue

            sym = tmp[-1]
            mem = sym.mem_entry_ref
            if not mem.is_bpf_val():
                continue

            r = _prepare_symbol_for_bound_checking(x, sym)
            ref, index, T = r
            if ref.has_flag(Instruction.BOUND_CHECK_FLAG):
                continue

            assert isinstance(ref, Instruction)
            assert isinstance(index, Instruction)

            _check_if_variable_index_should_be_masked(ref, index, blk, info)
            # debug('add bound check because binary operator access packet' , tag=MODULE_TAG)
            _add_bound_check(blk, r, current_function, info, bytes_mode=False, more=more)
            # Report for debuging
            tmp,_ = gen_code([inst], info)
            debug(f'Add a bound check before:\n    {tmp}', tag=MODULE_TAG)

        if inst.op == '=':
            self._track_value(lhs, rhs)


    def process_current_inst(self, inst, more):
        if inst.kind == clang.CursorKind.VAR_DECL:
            return self._handle_var_decl(inst, more)
        elif inst.kind == clang.CursorKind.BINARY_OPERATOR:
            return self._handle_binop(inst, more)

    def end_current_inst(self, inst, more):
        pass


def new_verifier_pass(inst, info, more):
    obj = Verifier.do(inst, info, more)
