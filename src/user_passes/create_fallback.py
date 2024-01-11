import itertools
import clang.cindex as clang

from log import error, debug
from instruction import *
from data_structure import BASE_TYPES
from sym_table import Scope
from user import USER_EVENT_LOOP_ENTRY
from user import Path

from passes.pass_obj import PassObject
from passes.clone import clone_pass


MODULE_TAG = '[Create Fallback]'
new_functions = []


fnum = 1
def _get_tmp_func_name():
    global fnum
    name = f'__f{fnum}'
    fnum += 1
    return name


def _generate_id_check(ids):
    assert len(ids) > 0 
    if_stmt = ControlFlowInst()
    if_stmt.kind = clang.CursorKind.IF_STMT

    # If the failure is for this path
    id_checks = []
    for i in ids:
        lhs_ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        lhs_ref.name = 'failure_number'
        lhs_ref.type = BASE_TYPES[clang.TypeKind.INT]
        rhs_ref = Literal(str(i), clang.CursorKind.INTEGER_LITERAL)
        check = BinOp(None)
        check.op = '=='
        check.lhs.add_inst(lhs_ref)
        check.rhs.add_inst(rhs_ref)
        id_checks.append(check)

    count_checks = len(id_checks)
    if count_checks > 1:
        or_op = BinOp(None)
        or_op.op = '||'
        or_op.lhs.add_inst(id_checks[0])
        it = itertools.islice(id_checks, 1, count_checks - 1)
        for check in it:
            or_op.rhs.add_inst(check)
            new_or_op = BinOp(None)
            new_or_op.op = '||'
            new_or_op.lhs.add_inst(or_op)
            or_op = new_or_op
        or_op.rhs.add_inst(id_checks[-1])
        cond = or_op
    else:
        cond = id_checks[0]
    if_stmt.cond.add_inst(cond)
    return if_stmt


def _get_call_inst(inst):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        return inst
    elif inst.kind == clang.CursorKind.BINARY_OPERATOR:
        if inst.op == '=' and inst.rhs.has_children():
            tmp_inst = inst.rhs.children[0]
            if tmp_inst.kind == clang.CursorKind.CALL_EXPR:
                return tmp_inst
    return None


def _starts_with_func_call(node, info):
    if not node.has_code():
        return None, None, None

    code = node.paths.code
    first_inst = code.children[0]
    call_inst = _get_call_inst(first_inst)

    if not call_inst:
        return None, None, None

    func = call_inst.get_function_def()
    if not func:
        return None, None, None
    assert func.may_fail

    # Define a new function
    clone_first_inst = clone_pass(first_inst)
    call_inst = _get_call_inst(clone_first_inst)
    assert call_inst is not None

    call_inst.name = _get_tmp_func_name()
    new_func = func.clone2(call_inst.name, Function.directory)
    new_func.body = Block(BODY)
    new_functions.append(new_func)
    func.update_symbol_table(info.sym_tbl.global_scope)
    return call_inst, new_func, clone_first_inst


def _process_node(node, info):
    debug('node:', id(node), 'count children:', len(node.children), tag=MODULE_TAG)
    debug('path ids:', node.path_ids, tag=MODULE_TAG)
    # debug('code:', node.paths.code.children, tag=MODULE_TAG)
    blk = Block(BODY)
    assert not node.is_empty()
    remove_first_inst = False

    for child in node.children:
        # Create a new function for each child that is in another function
        call_inst, new_func, first_inst = _starts_with_func_call(node, info)

        if new_func:
            debug('starts with a call to', new_func.name, tag=MODULE_TAG)
            with info.sym_tbl.with_func_scope(call_inst.name):
                body = _process_node(child, info)
            child.paths.func_obj = new_func
            child.paths.call_inst.append(call_inst)
            child.paths.code = body
        else:
            debug('just code', tag=MODULE_TAG)
            cur = info.sym_tbl.current_scope
            info.sym_tbl.current_scope = node.paths.scope
            body = _process_node(child, info)
            info.sym_tbl.current_scope = cur

        # Check if there are multiple failure path or just one!
        debug('still processing node:', id(node),
                'count children:', len(node.children), tag=MODULE_TAG)
        debug(node.path_ids, tag=MODULE_TAG)
        if len(node.path_ids) > 1:
            debug('Generating a id check', tag=MODULE_TAG)
            if_inst = _generate_id_check(child.path_ids)
            if new_func is None:
                if_inst.body = body
                # TODO: what is this?
                origin_symbols = child.paths.original_scope.symbols
                node.paths.original_scope.symbols.update(origin_symbols)
            else:
                remove_first_inst = True
                if_inst.body.add_inst(first_inst)
            blk.add_inst(if_inst)
        else:
            debug('no check was added', tag=MODULE_TAG)
            if new_func is None:
                blk.extend_inst(body.children)
                # TODO: what is this?
                origin_symbols = child.paths.original_scope.symbols
                node.paths.original_scope.symbols.update(origin_symbols)
            else:
                remove_first_inst = True
                blk.add_inst(first_inst)

    # Add the instructions associated with this node
    if node.has_code():
        insts = node.paths.code.get_children()
        if remove_first_inst:
            insts.pop(0)
        blk.extend_inst(insts)

    assert blk.has_children()
    node.paths.code = blk
    node.paths.scope = info.sym_tbl.current_scope
    return blk


def create_fallback_pass(inst, info, more):
    """
    Descripton:
    Walk the user program graph and creat functions handling fallback paths.

    Assumption:
    there should not be any function in the form of `__f{int}' these function
    names are used for handling fallback/failure paths.
    """
    root = info.user_prog.graph
    new_scope = Scope(info.sym_tbl.global_scope)
    info.sym_tbl.scope_mapping[USER_EVENT_LOOP_ENTRY] = new_scope
    with info.sym_tbl.with_func_scope(USER_EVENT_LOOP_ENTRY):
        _process_node(root, info)
    info.user_prog.fallback_funcs_def = new_functions
