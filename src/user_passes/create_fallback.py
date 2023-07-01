import itertools
import clang.cindex as clang

from log import error, debug
from instruction import *
from sym_table import Scope
from user import USER_EVENT_LOOP_ENTRY
from user import Path

from passes.pass_obj import PassObject
from passes.clone import clone_pass


MODULE_TAG = '[Create Fallback Pass]'
new_functions = []


fnum = 1
def _get_func_name():
    global fnum
    name = f'f{fnum}'
    fnum += 1
    return name


def _generate_id_check(ids):
    if_stmt = ControlFlowInst()
    if_stmt.kind = clang.CursorKind.IF_STMT

    # If the failure is for this path
    id_checks = []
    for i in ids:
        lhs_ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
        lhs_ref.name = 'failure_number'
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
    call_inst = None
    if inst.kind == clang.CursorKind.CALL_EXPR:
        call_inst = inst
    elif inst.kind == clang.CursorKind.BINARY_OPERATOR:
        if inst.op == '=' and inst.rhs.has_children():
            tmp_inst = inst.rhs.children[0]
            if tmp_inst.kind == clang.CursorKind.CALL_EXPR:
                call_inst = tmp_inst
    return call_inst


def _starts_with_func_call(node, info, child):
    if not node.has_code():
        return None, None, None

    code = node.paths.code
    if not code.has_children():
        return None, None, None

    first_inst = code.get_children()[0]
    func = None
    call_inst = _get_call_inst(first_inst)

    if call_inst:
        func = call_inst.get_function_def()
        if not func or not func.may_fail:
            call_inst = None

    if not call_inst:
        return None, None, None

    # Define a new function
    clone_first_inst = clone_pass(first_inst, info, PassObject())
    call_inst = _get_call_inst(clone_first_inst)
    assert call_inst is not None

    call_inst.name = _get_func_name()
    new_func = func.clone2(call_inst.name, Function.directory)
    new_func.body = Block(BODY)
    new_functions.append(new_func)

    # Create a new empty scope for the new function we want to define
    new_scope = Scope()
    info.sym_tbl.scope_mapping[call_inst.name] = new_scope
    for arg in new_func.args:
        new_scope.insert_entry(arg.name, arg.type_ref,
                clang.CursorKind.PARM_DECL, None)

    obj = child.paths
    obj.func_obj = new_func
    obj.call_inst = call_inst

    return call_inst, new_func, clone_first_inst



def _process_node(node, info):
    synth_orig_scope = False
    if node.paths is None:
        node.paths = Path()
        node.paths.original_scope = Scope()
        synth_orig_scope = True

    blk = Block(BODY)
    for child in node.children:
        call_inst, new_func, first_inst = _starts_with_func_call(node, info, child)
        if new_func is None:
            body = _process_node(child, info)
        else:
            with info.sym_tbl.with_func_scope(call_inst.name):
                body = _process_node(child, info)
                new_func.body = body

        # Check if there are multiple failure path or just one!
        if len(node.path_ids) > 1:
            if_inst = _generate_id_check(node.path_ids)
            if new_func is None:
                if_inst.body = body
            else:
                if_inst.body.add_inst(first_inst)
                # remove the first instruction
                node.paths.code.children.pop(0)
            blk.add_inst(if_inst)
        else:
            if new_func is None:
                blk.extend_inst(body.children)
            else:
                blk.add_inst(first_inst)
                node.paths.code.children.pop(0)

    if node.has_code():
        insts = node.paths.code.get_children()
        blk.extend_inst(insts)

    assert blk.has_children()
    node.paths.code = blk
    node.paths.scope = info.sym_tbl.current_scope
    return blk


def create_fallback_pass(inst, info, more):
    g = info.user_prog.graph

    new_scope = Scope()
    info.sym_tbl.scope_mapping[USER_EVENT_LOOP_ENTRY] = new_scope

    with info.sym_tbl.with_func_scope(USER_EVENT_LOOP_ENTRY):
        body = _process_node(g, info)
    info.user_prog.fallback_funcs_def = new_functions
    info.user_prog.entry_body = body
    return body