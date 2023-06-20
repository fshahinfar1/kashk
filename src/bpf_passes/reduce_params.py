import clang.cindex as clang
from log import error, debug
from data_structure import *
from instruction import *
from sym_table import SymbolTableEntry
from utility import indent 
from bpf_code_gen import gen_code
from passes.pass_obj import PassObject


PARAMETER_LIMIT = 5
EXTRA_PARAM_NAME = '__ex'
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


def _function_check_param_reduc(inst, func, info, more):
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
        for i in range(count_extra):
            param = func.args.pop()
            # TODO: do I need to maintain the symbol of this parameter?
            # I am passing a struct which might have a field that
            # points to the BPF context.
            sym = func_scope.delete(param.name)
            change.add_param(param)

        # Add a new parameter to the function
        ex_obj = StateObject(None)
        ex_obj.name = EXTRA_PARAM_NAME
        ex_obj.type = f'struct {change.struct_name} *'
        ex_obj.is_pointer = True
        T2 = MyType()
        T2.spelling = f'struct {change.struct_name}'
        T2.kind = clang.TypeKind.RECORD
        T = MyType()
        T.spelling = ex_obj.type
        T.under_type = T2
        T.kind = clang.TypeKind.POINTER
        ex_obj.type_ref = T
        func.args.append(ex_obj)
        sym = SymbolTableEntry(ex_obj.name, T, clang.CursorKind.PARM_DECL, None)
        func_scope.insert(sym)

        # Add this new struct to the definition list
        rec = Record(change.struct_name, change.list_of_params)
        rec.update_symbol_table(info.sym_tbl)
        text = rec.get_c_code()
        info.prog.add_declaration(text)
    
    # Go through the body of the function and replace the variables or check
    # for other function invocations.
    with info.sym_tbl.with_func_scope(inst.name):
        with remember_change_ctx(change):
            m = _do_pass(func.body, info, PassObject())
    func.body = m


def _handle_call(inst, info, more):
    func = inst.get_function_def()
    if not func:
        # Ignore this instruction. There is no change
        return inst

    # Check if the function was analysed before
    if inst.name not in _Change.updated_functions:
        _function_check_param_reduc(inst, func, info, more)

    # Check how this function was changed then, if needed, change how it is
    # invoked
    change = _Change.updated_functions[inst.name]
    count_extra = len(change.list_of_params)
    if not count_extra:
        # No change to the invocation of the function
        return inst
    
    # Create an instance of struct which should be passed to the function
    extra_args = [inst.args.pop() for i in range(count_extra)]
    decl = VarDecl(None)
    decl.type = change.struct_name
    # TODO: what if there are multiple extra args in a block?
    decl.name = '__ex'
    decl.is_record = True
    # TODO: How to implement a struct initialization?
    tmp = []
    for field, var in zip(change.list_of_params, extra_args):
        field_name = field.name
        var_name, _ = gen_code([var], info)
        tmp.append(f'.{field_name} = {var_name}')
    init_text = '{\n' + indent(',\n'.join(tmp)) + '\n}'
    decl.init.add_inst(Literal(init_text, CODE_LITERAL))
    # Add the struct definition to the line before calling the function
    blk = cb_ref.get(BODY)
    blk.append(decl)

    # Pass a reference of this struct to the function
    ref = Ref(None, kind=clang.CursorKind.DECL_REF_EXPR)
    ref.name = decl.name
    unary = UnaryOp(None)
    unary.op = '&'
    unary.child.add_inst(ref)
    inst.args.append(unary)
    
    return inst


def _handle_ref(inst, info, more):
    if current_change_ctx is None:
        # This is the body of BPF program
        return inst

    top_lvl_var_name = inst.name
    if inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
        if inst.owner:
            top_lvl_var_name = inst.owner[-1]
        else:
            # using c++ implicit `this'
            top_lvl_var_name = 'self'

    flag = current_change_ctx.should_update_ref(top_lvl_var_name)
    if flag:
        new_inst = inst.clone([])
        new_inst.owner.append(EXTRA_PARAM_NAME)
        new_inst.kind = clang.CursorKind.MEMBER_REF_EXPR
        return new_inst
    return inst


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        return _handle_call(inst, info, more)
    elif inst.kind in (clang.CursorKind.DECL_REF_EXPR,
                clang.CursorKind.MEMBER_REF_EXPR):
        return _handle_ref(inst, info, more)
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
    return new_inst


def reduce_params_pass(inst, info, more):
    return _do_pass(inst, info, more)
