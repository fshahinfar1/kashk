import clang.cindex as clang
from log import error, debug
from data_structure import *
from instruction import *
from my_type import MyType
from sym_table import SymbolTableEntry
from utility import indent, get_tmp_var_name, get_top_owner
from code_gen import gen_code
from passes.pass_obj import PassObject
from helpers.instruction_helper import decl_new_var
from var_names import EXTRA_PARAM_NAME


PARAMETER_LIMIT = 5
MODULE_TAG = '[Reduce Param Pass]'

cb_ref = CodeBlockRef()

current_change_ctx = None
@contextmanager
def remember_change_ctx(func):
    global current_change_ctx
    tmp = current_change_ctx
    current_change_ctx = func
    try:
        yield None
    finally:
        current_change_ctx = tmp


class _Change:
    """
    Store some information about the change made to a function signature
    """
    updated_functions = {}

    def __init__(self, name):
        self.__param_has_changed = set()
        self.list_of_params = []
        self.struct_name = f'__ex_{name}'
        self.func_name = name
        _Change.updated_functions[name] = self

    def add_param(self, state_obj):
        self.list_of_params.append(state_obj)
        self.__param_has_changed.add(state_obj.name)

    def should_update_ref(self, name):
        return name in self.__param_has_changed


def _function_check_param_reduce(inst, func, info, more):
    """
    Check if number of parameters of function exceed.
    1. Define a struct and put some of the parameters in that
    2. Change the signature of the function
    3. Recursively analyse the body of the called function
    """
    # Remember during this pass that I am going to change this function
    change = _Change(inst.name)

    count_args = len(func.args)
    if count_args > PARAMETER_LIMIT:
        # debug(MODULE_TAG, 'function', inst.name,
        #         'violates parameter limit! (it has:', count_args,')')

        func_scope = info.sym_tbl.scope_mapping.get(inst.name)
        assert func_scope is not None

        # Move some parameters to a struct
        count_extra = (count_args - PARAMETER_LIMIT) + 1
        # debug('Reduce parameters of', func.name, 'original args:', func.args)
        for i in range(count_extra):
            param = func.args.pop()
            # TODO: do I need to maintain the symbol of this parameter?
            # I am passing a struct which might have a field that
            # points to the BPF context.
            assert func_scope.lookup(param.name) is not None, f'Did not found {param.name} in the scope for function {func.name}'
            sym = func_scope.delete(param.name)
            change.add_param(param)

        # Add a new parameter to the function
        ex_obj = StateObject(None)
        ex_obj.name = EXTRA_PARAM_NAME
        T2 = MyType.make_simple(f'struct {change.struct_name}', clang.TypeKind.RECORD)
        T = MyType.make_pointer(T2)
        ex_obj.type_ref = T
        func.args.append(ex_obj)
        sym = SymbolTableEntry(ex_obj.name, T, clang.CursorKind.PARM_DECL, None)
        func_scope.insert(sym)

        # Add this new struct to the definition list
        rec = Record(change.struct_name, change.list_of_params)
        rec.update_symbol_table(info.sym_tbl)
        info.prog.add_declaration(rec)

    # Go through the body of the function and replace the variables or check
    # for other function invocations.
    with info.sym_tbl.with_func_scope(inst.name):
        with remember_change_ctx(change):
            m = _do_pass(func.body, info, PassObject())
    func.body = m


def _handle_call(inst, info, more):
    func = inst.get_function_def()
    if not func or func.is_empty():
        # Ignore this instruction. There is no change
        return inst

    # Check if the function was analysed before, otherwise process the function
    if inst.name not in _Change.updated_functions:
        _function_check_param_reduce(inst, func, info, more)

    # Check how this function was changed then, if needed, change how it is
    # invoked
    change = _Change.updated_functions[inst.name]
    count_extra = len(change.list_of_params)
    if not count_extra:
        # No change to the invocation of the function
        # debug(MODULE_TAG, inst.name, 'was not changed!')
        return inst

    # TODO: maybe it is better to copy the instruction and then modify it
    # Create an instance of struct which should be passed to the function
    extra_args = [inst.args.pop() for i in range(count_extra)]
    T = MyType.make_simple(f'struct {change.struct_name}',
            clang.TypeKind.RECORD)
    tmp_decl = []
    ref = decl_new_var(T, info, tmp_decl)
    tmp = []

    # Use multiple assignments to initialize the extra data-struct
    for field, var in zip(change.list_of_params, extra_args):
        # Check if the parameters passed to this function should be changed
        tmp_ref = Ref.build(field.name, field.type, True, True)
        tmp_ref.owner.append(ref)
        assign = BinOp.build(tmp_ref, '=', var)
        tmp.append(assign)
    # Add the struct definition to the line before calling the function
    blk = cb_ref.get(BODY)
    blk.extend(tmp_decl)
    blk.extend(tmp)
    # Pass a reference of this struct to the function
    unary = UnaryOp(None)
    unary.op = '&'
    unary.child.add_inst(ref)
    inst.args.append(unary)
    inst.set_modified(InstructionColor.ADD_ARGUMENT)
    return inst


def _handle_ref(inst, info, more):
    if current_change_ctx is None:
        # This is the body of BPF program
        return inst

    top_lvl_var_name = inst.name
    if inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
        if inst.owner:
            tmp = get_top_owner(inst)
            if tmp.kind == clang.CursorKind.DECL_REF_EXPR:
                top_lvl_var_name = tmp.name
            else:
                debug('The owner does not have a name', tag=MODULE_TAG)
                return inst
        else:
            # using c++ implicit `this'
            top_lvl_var_name = 'self'

    flag = current_change_ctx.should_update_ref(top_lvl_var_name)
    if not flag:
        # debug(MODULE_TAG, 'should not update')
        return inst
    new_inst = inst.clone([])
    struct_name = current_change_ctx.struct_name
    tmp = f'struct {struct_name}'
    tmp_T = MyType.make_simple(tmp, clang.TypeKind.RECORD)
    tmp_T = MyType.make_pointer(tmp_T)
    ex_ref = Ref.build(EXTRA_PARAM_NAME, tmp_T, False, red=True)

    last_owner = new_inst
    while last_owner.owner:
        last_owner = last_owner.owner[-1]
    last_owner.kind = clang.CursorKind.MEMBER_REF_EXPR
    last_owner.owner.append(ex_ref)
    assert len(last_owner.owner) == 1, f'too many owner was added ({len(last_owner.owner)})? owners: {last_owner.owner}'
    new_inst.kind = clang.CursorKind.MEMBER_REF_EXPR
    new_inst.color = InstructionColor.ORIGINAL
    new_inst.set_modified(InstructionColor.EXTRA_MEM_ACCESS)
    # debug(MODULE_TAG, 'updated!', new_inst, new_inst.owner)
    return new_inst


def _process_current_inst(inst, info, more):
    if inst.kind in (clang.CursorKind.DECL_REF_EXPR,
                clang.CursorKind.MEMBER_REF_EXPR):
        # debug(MODULE_TAG, 'handle ref:', inst)
        return _handle_ref(inst, info, more)
    return inst


def _end_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        return _handle_call(inst, info, more)
    return inst


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
    new_children = []

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
                        continue
                    new_child.append(new_inst)
            else:
                obj = PassObject.pack(lvl+1, tag, None)
                new_child = _do_pass(child, info, obj)
                assert new_child is not None
            new_children.append(new_child)

        new_inst = inst.clone(new_children)
        new_inst = _end_current_inst(new_inst, info, more)
    return new_inst


def reduce_params_pass(inst, info, more):
    return _do_pass(inst, info, more)
