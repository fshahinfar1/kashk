import itertools
import clang.cindex as clang

from bpf_code_gen import gen_code
from log import error, debug
from data_structure import *
from instruction import *
from sym_table import Scope
from user import USER_EVENT_LOOP_ENTRY


MODULE_TAG = '[Create Fallback Pass]'
cb_ref = CodeBlockRef()
new_functions = []


fnum = 1
def get_func_name():
    global fnum
    name = f'f{fnum}'
    fnum += 1
    return name


def _branch_to_path(p, ids):
    blk = cb_ref.get(BODY)

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
    if_stmt.body = p

    blk.add_inst(if_stmt)


def _process_node(node, info):
    # Paths are the codes that maybe run
    for path in node.paths:
        path.scope = info.sym_tbl.current_scope

        p = path.code
        failure_ids = node.path_ids
        if len(node.children) > 0:
            # The node has childrens, so
            # I expect the first instruction contain a function invocation
            first_inst = p.children[0]
            call_inst = None
            func = None
            if first_inst.kind == clang.CursorKind.CALL_EXPR:
                call_inst = first_inst
            elif first_inst.kind == clang.CursorKind.BINARY_OPERATOR:
                if first_inst.op == '=' and first_inst.rhs.has_children():
                    tmp_inst = first_inst.rhs.children[0]
                    if tmp_inst.kind == clang.CursorKind.CALL_EXPR:
                        call_inst = tmp_inst
                        func = call_inst.get_function_def()
                        if not func or not func.may_fail:
                            call_inst = None

            # The case which the called function fails
            if call_inst:
                original_name = call_inst.name
                # rename the function
                # call_inst.name += '_fail_path_' + '_'.join(map(str, failure_ids))
                call_inst.name = get_func_name()
                new_func = func.clone2(call_inst.name, Function.directory)
                new_func.body = Block(BODY)
                new_functions.append(new_func)

                # Create a new empty scope for the new function we want to define
                new_scope = Scope()
                info.sym_tbl.scope_mapping[call_inst.name] = new_scope
                for arg in new_func.args:
                    new_scope.insert_entry(arg.name, arg.type_ref,
                            clang.CursorKind.PARM_DECL, None)

                with info.sym_tbl.with_func_scope(call_inst.name):
                    with cb_ref.new_ref(new_func.body.tag, new_func.body):
                        for child in node.children:
                            _process_node(child, info)
            else:
                raise Exception('I have not implemented this case')

        _branch_to_path(p, failure_ids)


def create_fallback_pass(inst, info, more):
    # TODO: The user program graph is not generated in a way that supports all
    # the cases. It needs improvement.
    # TODO: create the state loading and path selection code here
    # TODO: load the failure_number
    entry = Block(BODY)
    info.user_prog.entry_body = entry
    g = info.user_prog.graph

    new_scope = Scope()
    info.sym_tbl.scope_mapping[USER_EVENT_LOOP_ENTRY] = new_scope

    with info.sym_tbl.with_func_scope(USER_EVENT_LOOP_ENTRY):
        with cb_ref.new_ref(entry.tag, entry):
            # _do_pass(inst, info, more)
            _process_node(g, info)
    info.user_prog.fallback_funcs_def = new_functions
    return entry
