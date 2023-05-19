import clang.cindex as clang
from utility import get_code, report_on_cursor, visualize_ast, get_owner
from data_structure import *
from understand_logic import gather_instructions_from, gather_instructions_under
from sym_table import *


COROUTINE_FUNC_NAME = ('await_resume', 'await_transform', 'await_ready', 'await_suspend')


def __function_is_of_interest(inst):
    if inst.is_method:
        # TODO: filter based on methods of types we do not want to have
        return True
        # for o in inst.owner:
        #     # TODO: i need more information from the owner not just its name
        #     if o == 'string':
        #         return False
    if inst.name.startswith('operator'):
        # TODO: I do not want operators for now. But It would be good to
        # support it as another function decleration and invocation
        return False
    return True


def __get_func_name(inst, info):
    func_name = '__this_function_name_is_not_defined__'
    if inst.is_method:
        # find the object having this method
        owner = list(reversed(inst.owner))
        func_name = []
        obj = info.scope
        for x in owner:
            obj = obj.get(x)
            if obj is None:
                break
            func_name.append(obj.type)
            if not obj:
                raise Exception(f'Object not found: {obj}')
        func_name.append(inst.name)
        func_name = '_'.join(func_name)
    else:
        func_name = inst.name
    return func_name


def __get_func_args(inst, info):
    args = []
    for x in inst.cursor.get_arguments():
        arg = gather_instructions_from(x, info)
        args.extend(arg)
    return args


def __add_func_definition(inst, info):
    f = Function(inst.name, inst.func_ptr)
    f.is_method = inst.is_method
    if f.is_method:
        ref_name = inst.owner[0]
        ref_state_obj = info.scope.get(ref_name)
        if ref_state_obj is not None:
            ref_state = ref_state_obj.clone()
            ref_state.is_ref = True
            # ref_state = f'{ref_state_obj.type} {ref_state_obj.name}'
        else:
            ref_state = f'T {ref_name}'
        f.args = [ref_state] + f.args

    # Recursively analize the function body
    if f.body_cursor:
        T = inst.cursor.result_type
        entry = SymbolTableEntry(inst.name, T, 'function', None)
        info.sym_tbl.insert(entry)

        # Create a new scope for the function
        info.sym_tbl.new_scope()

        # Process function parameters
        for arg in f.cursor.get_arguments():
            arg_name = arg.spelling
            arg_type = arg.type.spelling
            arg_entry = SymbolTableEntry(arg_name, arg_type, 'parameter', None)
            info.sym_tbl.insert(arg_entry)

        # Process function body recursively
        f.body = gather_instructions_under(f.body_cursor, info)

        # Restore the parent scope after function processing is done
        info.sym_tbl.free_scope()

        info.prog.add_declaration(f)


def understand_call_expr(c, info):
    tmp_func_name = c.spelling
    if tmp_func_name in COROUTINE_FUNC_NAME:
        # Ignore these
        return None

    # A call to the function
    inst = Call(c)
    inst.name = __get_func_name(inst, info)
    inst.args = __get_func_args(inst, info)

    # check if function is defined
    if __function_is_of_interest(inst) and inst.name not in Function.directory:
        __add_func_definition(inst, info)

    return inst


