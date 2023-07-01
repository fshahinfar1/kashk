import clang.cindex as clang
from log import error, debug
from sym_table import Scope, SymbolAccessMode
from utility import report_on_cursor
from instruction import *
from data_structure import MyType


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
    if inst.name == 'conn':
        # TODO: figure out what I need to do in this case
        return True
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

    # debug(path.code.children)
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
                sym.is_accessed = SymbolAccessMode.FIRST_WRITE
            else:
                sym.is_accessed = SymbolAccessMode.HAS_READ
                path.var_deps.add(sym)
                # debug('external:', inst.name, 'type:', orig_sym.type.spelling,
                #         'Context:', get_context_name(ctx))
                if ctx == LHS:
                    # debug(parent_bin_op.op)
                    pass
    else:
        if ctx == LHS and parent_bin_op.op == '=':
            sym.is_accessed = SymbolAccessMode.FIRST_WRITE
        else:
            sym.is_accessed = SymbolAccessMode.HAS_READ


def _analyse_var_dep_for_path(path, info):
    block = path.code

    # DFS
    queue = list(_get_children(block, None))
    while queue:
        inst, ctx, parent_bin_op = queue.pop()

        if inst.kind == clang.CursorKind.VAR_DECL:
            sym = path.original_scope.lookup(inst.name)
            if sym is not None:
                path.scope.insert_entry(inst.name, sym.type, inst.kind, inst)
            else:
                T = MyType()
                T.spelling = inst.type
                path.scope.insert_entry(inst.name, T, inst.kind, inst)
            # debug('learn about:', sym.name)
        elif inst.kind == clang.CursorKind.DECL_REF_EXPR:
            _handle_reference(path, inst, info, ctx, parent_bin_op)
        elif inst.kind == clang.CursorKind.BINARY_OPERATOR:
            parent_bin_op = inst

        queue.extend(_get_children(inst, parent_bin_op))


def _remove_unused_args(func_obj, call_inst, scope):
    remove = []
    for i, arg in enumerate(func_obj.args):
        sym = scope.lookup(arg.name)
        # print(arg.name, p.code.children, p.scope, func_obj.name)
        assert sym is not None
        if sym.is_accessed != SymbolAccessMode.HAS_READ:
            # debug(f'The variable {sym.name} is not needed in function argument of {func_obj.name}')
            remove.append(i)
        else:
            # debug(f'The variable {sym.name} is needed at {func_obj.name}')
            pass

    for already_poped, pos in enumerate(remove):
        pop_index = pos - already_poped
        func_obj.args.pop(pop_index)
        call_inst.args.pop(pop_index)


def _process_node(node, info):
    for child in node.children:
        _process_node(child, info)

        # TODO: seperate it for different paths.
        # Every variable that is needed in a child node is also needed in the
        # parent because parent does not know about them.
        for d in child.paths.var_deps:
            node.paths.var_deps.add(d)

        child_p = child.paths
        if child_p.func_obj is not None:
            _remove_unused_args(child_p.func_obj, child_p.call_inst, child_p.scope)

    if node.has_code():
        _analyse_var_dep_for_path(node.paths, info)


def var_dependency_pass(inst, info):
    root = info.user_prog.graph
    _process_node(root, info)
