import clang.cindex as clang
from log import error, debug
from sym_table import Scope
from utility import report_on_cursor
from instruction import *


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


def _get_children(obj, *args):
    src = obj.get_children_context_marked()
    res = []
    for child, tag in src:
        if isinstance(child, list):
            more_fields = []
            for x in args:
                more_fields.append([x] * len(child))
            res.extend(zip(child, [tag] * len(child), *more_fields))
        else:
            res.append((child, tag, *args))
    res.reverse()
    return res


def _should_not_share_variable(inst, sym, info):
    if inst.bpf_ignore:
        return True
    if 'asio::' in sym.type.spelling:
        return True
    if sym.name == info.rd_buf.name or sym.name == info.wr_buf.name:
        return True
    return False


def _handle_reference(path, inst, info, ctx, parent_bin_op):
    # TODO: since the scope is built before hand, the definitions that
    # come later are also present in this scope.
    # TODO: or if the variable is define before the failure region but
    # in this scope!
    sym, scope = path.scope.lookup2(inst.name)
    is_local = sym is not None and scope == path.scope
    if not is_local:
        orig_sym = path.original_scope.lookup(inst.name)
        if orig_sym is None:
            error(f'Variable {inst.name} was not found in the symbol table! Assuming it is not needed in userspace')
        elif _should_not_share_variable(inst, orig_sym, info):
            # debug('not share:', inst.name, 'type:', orig_sym.type.spelling)
            pass
        else:
            sym = path.scope.insert_entry(inst.name, orig_sym.type, orig_sym.kind, None)
            if ctx == LHS and parent_bin_op.op == '=':
                # writing to this unknow variable --> I do not need to share the result
                # debug(f'not caring about {sym.name}')
                pass
            else:
                path.var_deps.add(sym)
                debug('external:', inst.name, 'type:', orig_sym.type.spelling,
                        'Context:', get_context_name(ctx))



def _analyse_var_dep_for_path(path, info):
    block = path.code

    # DFS
    queue = list(_get_children(block, None))
    while queue:
        inst, ctx, parent_bin_op = queue.pop()

        if inst.kind == clang.CursorKind.VAR_DECL:
            sym = path.original_scope.lookup(inst.name)
            path.scope.insert_entry(inst.name, sym.type, inst.kind, inst)
            # debug('learn about:', sym.name)
        elif inst.kind == clang.CursorKind.DECL_REF_EXPR:
            _handle_reference(path, inst, info, ctx, parent_bin_op)
        elif inst.kind == clang.CursorKind.BINARY_OPERATOR:
            parent_bin_op = inst

        queue.extend(_get_children(inst, parent_bin_op))


def _process_node(node, info):
    for c in node.children:
        _process_node(c, info)
        for p2 in node.paths:
            for p in c.paths:
                for d in p.var_deps:
                    p2.var_deps.add(d)

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
