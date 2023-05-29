import itertools
import clang.cindex as clang

from log import error, debug
from data_structure import Function, BinOp
from dfs import DFSPass

MODULE_TAG = 'Verfier Pass'


def is_value_from_bpf_ctx(inst, info):
    """
    Check if an instruction result is a value from the BPF context memory
    region
    """
    if inst.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        if is_bpf_ctx_ptr(inst.array_ref[0], info):
            return True
    elif inst.kind == clang.CursorKind.UNARY_OPERATOR:
        if is_bpf_ctx_ptr(inst.child[0], info):
            return True
    return False


def is_bpf_ctx_ptr(inst, info):
    """
    Check if an instruction result is a pointer to the BPF context memory
    region
    """
    # TODO: this is incomplete
    if inst.kind == clang.CursorKind.DECL_REF_EXPR:
        # A simple variable reference
        sym = info.sym_tbl.lookup(inst.name)
        if sym:
            if sym.is_bpf_ctx:
                return True
    elif inst.kind == clang.CursorKind.BINARY_OPERATOR:
        # A pointer arithmatic or assignment
        op_is_good = inst.op in itertools.chain(BinOp.ARITH_OP, BinOp.ASSIGN_OP)
        if op_is_good:
            if (is_bpf_ctx_ptr(inst.lhs[0], info)
                    or is_bpf_ctx_ptr(inst.rhs[0], info)):
                return True
    elif inst.kind == clang.CursorKind.UNARY_OPERATOR and inst.op == '&':
        if is_value_from_bpf_ctx(inst.child[0], info):
            return True
    return False


def add_verifier_checks(insts, info):
    ops = []
    q = list()
    for i in reversed(insts):
        q.append((i, 0))
    while q:
        inst, lvl = q.pop()
        # debug('  '*lvl, inst)

        # Assignment
        if inst.kind == clang.CursorKind.BINARY_OPERATOR and inst.op == '=':
            assert len(inst.lhs) == 1
            assert len(inst.rhs) == 1
            lhs_is_ptr = is_bpf_ctx_ptr(inst.lhs[0], info)
            rhs_is_ptr = is_bpf_ctx_ptr(inst.rhs[0], info)
            if inst.lhs[0].kind == clang.CursorKind.DECL_REF_EXPR:
                if rhs_is_ptr:
                    sym = info.sym_tbl.lookup(inst.lhs[0].name)
                    sym.is_bpf_ctx = True
                    debug(sym.name, 'is ctx ptr')
                elif not rhs_is_ptr and lhs_is_ptr:
                    sym = info.sym_tbl.lookup(inst.lhs[0].name)
                    sym.is_bpf_ctx = False
                    debug(sym.name, 'is something else')


        # Step into the function
        if inst.kind == clang.CursorKind.CALL_EXPR:
            func = Function.directory.get(inst.name)
            if func:
                # Find which arguments are context pointer before switching the
                # scope
                pos_of_ctx_ptrs = []
                for pos, a in enumerate(inst.args):
                    if is_bpf_ctx_ptr(a, info):
                        pos_of_ctx_ptrs.append(pos)

                # Switch the context, then update the context flag in this
                # context
                scope = info.sym_tbl.scope_mapping.get(inst.name)
                assert scope is not None
                cur = info.sym_tbl.current_scope
                info.sym_tbl.current_scope = scope
                # debug('function call:', inst.name, 'args:', inst.args)

                for pos in pos_of_ctx_ptrs:
                        param = func.args[pos]
                        sym = info.sym_tbl.lookup(param.name)
                        sym.is_bpf_ctx = True
                        # TODO: do I need to turn the flag off when removing
                        # the scope of the function (may in another run the
                        # parameter is not a pointer to the context)

                modified = add_verifier_checks(func.body, info)
                info.sym_tbl.current_scope = cur
                continue

        for i in reversed(inst.get_children()):
            # for i in reversed(c):
            q.append((i, lvl+1))
