import clang.cindex as clang
from log import error, debug
from sym_table import Scope


MODULE_TAG = '[Var Dependency]'


def _is_ref_local(ref, info):
    sym, scope = info.sym_tbl.lookup2(ref.name)
    if not scope:
        # is not defined
        error(MODULE_TAG, f'variable `{ref.name}\' not defined in any scope! it was not expected.')
        return False
    if scope != info.sym_tbl.current_scope:
        # variable is from another (parent) scope
        return False
    return True


def _analyse_var_dep_for_path(path, info):
    block = path.code

    # DFS
    queue = list(reversed(block.get_children()))
    while queue:
        inst = queue.pop()

        if inst.kind == clang.CursorKind.VAR_DECL:
            sym = path.original_scope.lookup(inst.name)
            path.scope.insert_entry(inst.name, sym.type, inst.kind, inst)
            debug('learn about:', sym.name)
        elif inst.kind == clang.CursorKind.DECL_REF_EXPR:
            # TODO: since the scope is built before hand, the definitions that
            # come later are also present in this scope.
            # TODO: or if the variable is define before the failure region but
            # in this scope!
            sym, scope = path.scope.lookup2(inst.name)
            is_local = sym is not None and scope == path.scope
            if not is_local:
                orig_sym = path.original_scope.lookup(inst.name)
                assert orig_sym is not None
                debug('external:', inst.name, 'type:', orig_sym.type.spelling)
            else:
                debug('local:', inst.name)

        queue.extend(reversed(inst.get_children()))


def _process_node(node, info):
    for c in node.children:
        _process_node(c, info)

    for p in node.paths:
        _analyse_var_dep_for_path(p, info)


def var_dependency_pass(inst, info):
    root = info.user_prog.graph

    # test_scope = Scope()
    # t_shar = info.sym_tbl.shared_scope
    # t_glob = info.sym_tbl.global_scope
    # t_cur = info.sym_tbl.current_scope
    # info.sym_tbl.shared_scope = test_scope
    # info.sym_tbl.global_scope = test_scope
    # info.sym_tbl.current_scope = test_scope
    # TODO: maybe share the global variables between both BPF and Userspace

    _process_node(root, info)

    # info.sym_tbl.shared_scope = t_shar
    # info.sym_tbl.global_scope = t_glob
    # info.sym_tbl.current_scope = t_cur
