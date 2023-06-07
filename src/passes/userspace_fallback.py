import itertools
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *

from sym_table import SymbolTableEntry


MODULE_TAG = '[Fallback Pass]'

current_function = None
cb_ref = CodeBlockRef()

FLAG_PARAM_NAME = '__fail_flag'


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
    _, ctx, _ = more

    blk = cb_ref.get(BODY)
    ret_val = None

    flag_ref = Ref(None, kind=clang.CursorKind.DECL_REF_EXPR)
    flag_ref.name = FLAG_PARAM_NAME

    before_func_call = []
    func_call = inst
    after_func_call = []

    if ctx != BODY:
        # Let's move the function outside of argument section
        if func.return_type != 'void':
            tmp_var_name = 'tmp'
            # Declare tmp
            tmp_decl = VarDecl(None)
            tmp_decl.name = tmp_var_name
            tmp_decl.type = func.return_type
            tmp_decl.state_obj = None
            before_func_call.append(tmp_decl)
            # Assign function return value to tmp
            tmp_ref = Ref(None, kind=clang.CursorKind.DECL_REF_EXPR)
            tmp_ref.name = tmp_var_name
            bin_op = BinOp(None)
            bin_op.op = '='
            bin_op.lhs.add_inst(tmp_ref)
            bin_op.rhs.add_inst(inst)
            func_call = bin_op
            # replace the function call with the variable
            ret_val = tmp_ref.clone([])
        else:
            raise Exception('Not implemented yet!')

    if func.may_succeed:
        ## we need to pass a flag
        # TODO: check that we only update the signature once
        # Update the signature of the function
        flag_obj = StateObject(None)
        flag_obj.name = FLAG_PARAM_NAME
        flag_obj.type = 'char *'
        flag_obj.is_pointer = True
        T2 = MyType()
        T2.spelling = 'char'
        T2.kind = clang.TypeKind.SCHAR
        T = MyType()
        T.spelling = flag_obj.type
        T.under_type = T2
        T.kind = clang.TypeKind.POINTER
        flag_obj.real_type = T
        func.args.append(flag_obj)
        # Update the flag to the symbol table for the function scope
        scope = info.sym_tbl.scope_mapping.get(inst.name)
        assert scope is not None
        entry = SymbolTableEntry(flag_obj.name, T, clang.CursorKind.PARM_DECL, None)
        scope.insert(entry)

        # Pass the flag when invoking the function
        # First check if we need to allocate the flag on the stack memory
        sym = info.sym_tbl.lookup(FLAG_PARAM_NAME)
        if not sym:
            # declare a local variable
            flag_decl = VarDecl(None)
            flag_decl.name = flag_obj.name
            flag_decl.type = 'char'
            flag_decl.state_obj = flag_obj
            zero = Literal('0', clang.CursorKind.INTEGER_LITERAL)
            flag_decl.init.add_inst(zero)
            before_func_call.append(flag_decl)

        # Now add the argument to the invocation instruction
        # TODO: update every invocation of this function with the flag parameter
        addr_op = UnaryOp(None)
        addr_op.op = '&'
        addr_op.child.add_inst(flag_ref)
        inst.args.append(addr_op)

        # TODO: it adds the code before the function invocation! Fix it.
        # check if function fail
        tmp = Literal('/* check if function fail */\n', CODE_LITERAL)
        after_func_call.append(tmp)
        if current_function == None:
            # we are in the bpf function
            return_stmt = '/*Go to userspace */\n  return SK_PASS;\n'
        else:
            return_stmt = 'return ({func.return_type})0;'
        check_flag = f'if({FLAG_PARAM_NAME} == 1) {{\n  {return_stmt}\n}}\n'
        tmp = Literal(check_flag, CODE_LITERAL)
        after_func_call.append(tmp)


        # Analyse the called function.
        with remember_func(func):
            with info.sym_tbl.with_func_scope(inst.name):
                modified = _do_pass(func.body, info, (0, BODY, None))
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
            if func.return_type == 'void':
                tmp_stmt = 'return;'
            else:
                tmp_stmt = f'return ({func.return_type}){0};'
            return_stmt = ('/* Return from this point to the caller */\n'
                    + f'{tmp_stmt}')
            tmp = Literal(return_stmt, CODE_LITERAL)
            after_func_call.append(tmp)
        else:
            # The caller knows we are going to fail (this function never
            # succeed)
            # The next check is just for debugging
            if current_function:
                assert (current_function.may_fail and not
                        current_function.may_succeed)

    blk.extend(before_func_call)
    blk.append(func_call)
    blk.extend(after_func_call)
    return ret_val


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        func = inst.get_function_def()
        # we only need to investigate functions that may fail
        if func and func.may_fail:
            return _handle_function_may_fail(inst, func, info, more)
    return inst


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more
    new_children = []

    # TODO: remember body seems to be redundant, one assignment could solve the
    # issue?
    with cb_ref.new_ref(ctx, parent_list):
        # Process current instruction
        inst = _process_current_inst(inst, info, more)
        if inst is None:
            return None

        # Continue deeper
        for child, tag in inst.get_children_context_marked():
            if isinstance(child, list):
                new_child = []
                for i in child:
                    new_inst = _do_pass(i, info, (lvl+1, tag, new_child))
                    if new_inst is None:
                        continue
                    new_child.append(new_inst)
            else:
                new_child = _do_pass(child, info, (lvl+1, tag, None))
                assert new_child is not None
            new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def userspace_fallback_pass(inst, info, more):
    return _do_pass(inst, info,more)
