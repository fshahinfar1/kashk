import itertools
import clang.cindex as clang

from log import error, debug
from utility import indent
from data_structure import *
from instruction import *

from sym_table import SymbolTableEntry
from passes.pass_obj import PassObject


MODULE_TAG = '[Fallback Pass]'

current_function = None
cb_ref = CodeBlockRef()

FLAG_PARAM_NAME = '__fail_flag'


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
    flag_ref.name = FLAG_PARAM_NAME

    before_func_call = []
    after_func_call = []

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
        flag_obj.type_ref = T
        func.args.append(flag_obj)
        # Update the flag to the symbol table for the function scope
        scope = info.sym_tbl.scope_mapping.get(inst.name)
        assert scope is not None
        entry = SymbolTableEntry(flag_obj.name, T, clang.CursorKind.PARM_DECL, None)
        scope.insert(entry)

        # Pass the flag when invoking the function
        # First check if we need to allocate the flag on the stack memory
        sym = info.sym_tbl.lookup(FLAG_PARAM_NAME)
        is_on_the_stack = not sym
        if is_on_the_stack:
            # declare a local variable
            flag_decl = VarDecl(None)
            flag_decl.name = flag_obj.name
            flag_decl.type = BASE_TYPES[clang.TypeKind.SCHAR]
            flag_decl.state_obj = flag_obj
            zero = Literal('0', clang.CursorKind.INTEGER_LITERAL)
            flag_decl.init.add_inst(zero)
            before_func_call.append(flag_decl)

        # Now add the argument to the invocation instruction
        # TODO: update every invocation of this function with the flag parameter
        if is_on_the_stack:
            # pass a reference
            addr_op = UnaryOp(None)
            addr_op.op = '&'
            addr_op.child.add_inst(flag_ref)
            inst.args.append(addr_op)
        else:
            inst.args.append(flag_ref)

        # check if function fail
        tmp = Literal('/* check if function fail */\n', CODE_LITERAL)
        after_func_call.append(tmp)
        if current_function == None:
            code = '''
__adjust_skb_size(skb, sizeof(struct meta));
if (((void *)(__u64)skb->data + sizeof(struct meta))  > (void *)(__u64)skb->data_end) {
  return SK_DROP;
}
struct meta *__m = (void *)(__u64)skb->data;
'''
            # TODO: I need to know the failure number and failure structure
            meta = info.user_prog.declarations[0]
            store = []
            for f in meta.fields: 
                store.append(f'__m->{f.name} = {f.name};')

            code += '\n'.join(store) + '\n'

            # we are in the bpf function
            return_stmt = code + '/*Go to userspace */\nreturn SK_PASS;\n'
        elif func.return_type.spelling == 'void':
            return_stmt = 'return;'
        else:
            return_stmt = f'return ({func.return_type.spelling})0;'
        return_stmt = indent(return_stmt)
        check_flag = f'if({FLAG_PARAM_NAME} == 1) {{\n{return_stmt}\n}}\n'
        tmp = Literal(check_flag, CODE_LITERAL)
        after_func_call.append(tmp)

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
            after_func_call.append(ToUserspace.from_func_obj(func))
        else:
            # The caller knows we are going to fail (this function never
            # succeed)
            # The next check is just for debugging
            if current_function:
                assert (current_function.may_fail and not
                        current_function.may_succeed)

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
    if inst.kind == clang.CursorKind.CALL_EXPR:
        func = inst.get_function_def()
        # we only need to investigate functions that may fail
        if func and func.may_fail:
            return _handle_function_may_fail(inst, func, info, more)
    return inst


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
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
                    obj = PassObject.pack(lvl+1, tag, new_child)
                    new_inst = _do_pass(i, info, obj)
                    if new_inst is None:
                        if inst.tag == BODY:
                            continue
                        else:
                            return None

                    after = []
                    while new_child and isinstance(new_child[-1], After):
                        after.append(new_child.pop())
                    new_child.append(new_inst)
                    for a in after:
                        new_child.extend(a.box)

                    if i.kind == TO_USERSPACE_INST:
                        break
            else:
                obj = PassObject.pack(lvl+1, tag, parent_list)
                new_child = _do_pass(child, info, obj)
                if new_child is None:
                    return None
            new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def userspace_fallback_pass(inst, info, more):
    return _do_pass(inst, info, more)
