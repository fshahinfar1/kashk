import itertools
import clang.cindex as clang

from log import error, debug
from utility import indent
from template import prepare_meta_data
from data_structure import *
from instruction import *

from sym_table import SymbolTableEntry
from passes.pass_obj import PassObject

from bpf_code_gen import gen_code

from bpf_passes.transform_vars import FAIL_FLAG_NAME


MODULE_TAG = '[Fallback Pass]'

current_function = None
cb_ref = CodeBlockRef()


class After:
    def __init__(self, box):
        self.box = box


@contextmanager
def remember_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield None
    finally:
        current_function = tmp


def _handle_function_may_fail(inst, func, info, more):
    ctx = more.ctx

    blk = cb_ref.get(BODY)

    flag_ref = Ref(None, kind=clang.CursorKind.DECL_REF_EXPR)
    flag_ref.name = FAIL_FLAG_NAME
    flag_ref.type = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])

    before_func_call = []
    after_func_call = []

    if func.may_succeed:
        ## we need to pass a flag
        flag_obj = StateObject(None)
        flag_obj.name = flag_ref.name
        T = flag_ref.type
        flag_obj.type_ref = T

        assert (func.change_applied & Function.FAIL_FLAG) != 0, f'The fail flag should alread be added to the function definition (func:{func.name})'

        # Pass the flag when invoking the function
        # First check if we need to allocate the flag on the stack memory
        sym = info.sym_tbl.lookup(FAIL_FLAG_NAME)
        is_on_the_stack = sym is not None
        if not is_on_the_stack:
            # declare a local variable
            flag_decl = VarDecl(None)
            flag_decl.name = flag_obj.name
            flag_decl.type = flag_ref.type.under_type
            flag_decl.state_obj = flag_obj
            zero = Literal('0', clang.CursorKind.INTEGER_LITERAL)
            flag_decl.init.add_inst(zero)
            before_func_call.append(flag_decl)

        # Now add the argument to the invocation instruction
        # TODO: update every invocation of this function with the flag parameter
        if not is_on_the_stack:
            # pass a reference
            addr_op = UnaryOp(None)
            addr_op.op = '&'
            flag_ref.type = flag_decl.type
            addr_op.child.add_inst(flag_ref)
            inst.args.append(addr_op)
        else:
            inst.args.append(flag_ref)

        tmp = Literal('/* check if function fail */\n', CODE_LITERAL)
        after_func_call.append(tmp)

        # How should we return to from this function?
        return_stmt = ToUserspace.from_func_obj(current_function)

        if current_function == None:
            assert len(func.path_ids) > 0

            first_failure_case = None
            prev_failure_case = None

            failure_flag_ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
            failure_flag_ref.name = FAIL_FLAG_NAME
            failure_flag_ref.type = BASE_TYPES[clang.TypeKind.SCHAR]

            for failure_number in func.path_ids:
                # TODO: change declaration to a dictionary instead of array
                meta = info.user_prog.declarations[failure_number-1]
                prepare_meta_code = prepare_meta_data(failure_number, meta, info.prog)

                # Check the failure number
                int_literal = Literal(str(failure_number), clang.CursorKind.INTEGER_LITERAL)
                cond = BinOp.build_op(failure_flag_ref, '==', int_literal)
                if_inst = ControlFlowInst.build_if_inst(cond)
                if_inst.body.add_inst(prepare_meta_code)
                if_inst.body.add_inst(ToUserspace.from_func_obj(current_function))

                if prev_failure_case is not None:
                    prev_failure_case.other_body.add_inst(if_inst)
                else:
                    first_failure_case = if_inst
                prev_failure_case = if_inst
            # The code that should run when there is a failure
            return_stmt = first_failure_case

            int_literal = Literal('0', clang.CursorKind.INTEGER_LITERAL)
            cond = BinOp.build_op(failure_flag_ref, '!=', int_literal)
            if_inst = ControlFlowInst.build_if_inst(cond)
            if_inst.body.add_inst(return_stmt)
            after_func_call.append(if_inst)

        # Analyse the called function.
        with remember_func(func):
            with info.sym_tbl.with_func_scope(inst.name):
                modified = _do_pass(func.body, info, PassObject())
        assert modified is not None
        func.body = modified
    else:
        # The callee function is going to fail
        if current_function and current_function.may_succeed:
            # We need to notify the caller
            true = Literal('1', clang.CursorKind.INTEGER_LITERAL)

            val_op = UnaryOp(None)
            val_op.op = '*'
            val_op.child.add_inst(flag_ref)

            bin_op = BinOp(None)
            bin_op.op = '='
            bin_op.lhs.add_inst(val_op)
            bin_op.rhs.add_inst(true)

            after_func_call.append(bin_op)
            after_func_call.append(ToUserspace.from_func_obj(current_function))
        else:
            # The caller knows we are going to fail (this function never
            # succeed)
            # The next check is just for debugging
            if current_function:
                assert (current_function.may_fail and not
                        current_function.may_succeed)

            if not current_function:
                # We are in the main BPF function, we should fallback t user
                after_func_call.append(ToUserspace.from_func_obj(current_function))


        # Also take a look at the body of the called function. We may want to
        # remove everything after failure point.
        with remember_func(func):
            with info.sym_tbl.with_func_scope(inst.name):
                modified = _do_pass(func.body, info, PassObject())
        assert modified is not None
        func.body = modified

    blk.extend(before_func_call)
    blk.append(After(after_func_call))
    return inst


def _process_current_inst(inst, info, more):
    # text, _ = gen_code([inst, ], info)
    # print(text)
    if inst.kind == clang.CursorKind.CALL_EXPR:
        func = inst.get_function_def()
        # we only need to investigate functions that may fail
        if func and not func.is_empty() and func.may_fail:
            # debug(MODULE_TAG, func, func.may_succeed, func.may_fail)
            return _handle_function_may_fail(inst, func, info, more)
    elif inst.kind == TO_USERSPACE_INST and current_function is None:
        # Found a split point on the BPF entry function
        failure_number = inst.path_id
        meta = info.user_prog.declarations[failure_number - 1]
        prepare_pkt = prepare_meta_data(failure_number, meta, info.prog)
        blk = cb_ref.get(BODY)
        blk.append(prepare_pkt)
    return inst


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
    new_children = []

    with cb_ref.new_ref(ctx, parent_list):
        # Process current instruction
        inst = _process_current_inst(inst, info, more)
        if inst is None:
            debug(MODULE_TAG, 'remove instruction:', inst)
            return None

        # Continue deeper
        for child, tag in inst.get_children_context_marked():
            if isinstance(child, list):
                new_child = []
                for i in child:
                    obj = PassObject.pack(lvl+1, tag, new_child)
                    new_inst = _do_pass(i, info, obj)
                    if new_inst is None:
                        if inst.tag == BODY:
                            debug(MODULE_TAG, 'remove instruction from body:', inst)
                            continue
                        else:
                            debug(MODULE_TAG, 'remove instruction:', inst)
                            return None

                    after = []
                    while new_child and isinstance(new_child[-1], After):
                        after.append(new_child.pop())
                    new_child.append(new_inst)
                    for a in after:
                        new_child.extend(a.box)

                    if i.kind == TO_USERSPACE_INST:
                        # debug(MODULE_TAG, 'Found to Userspace trim the code')
                        break
            else:
                obj = PassObject.pack(lvl+1, tag, parent_list)
                new_child = _do_pass(child, info, obj)
                if new_child is None:
                    debug(MODULE_TAG, 'remove instruction:', inst)
                    return None
            new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def userspace_fallback_pass(inst, info, more):
    return _do_pass(inst, info, more)
