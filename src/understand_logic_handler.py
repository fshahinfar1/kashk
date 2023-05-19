import clang.cindex as clang
from utility import get_code, report_on_cursor, visualize_ast, get_owner
from log import error, debug
from data_structure import *
from understand_logic import gather_instructions_from, gather_instructions_under
from sym_table import *


COROUTINE_FUNC_NAME = ('await_resume', 'await_transform', 'await_ready', 'await_suspend')


def __function_is_of_interest(inst):
    """
    Decide if the function should also be defined in BPF code
    """
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
    func_name = inst.cursor.spelling
    debug('++', func_name)
    if inst.is_method:
        cls = info.sym_tbl.lookup('__class__')
        debug('is_method of', cls)
        if len(inst.owner) == 0:
            func_name = f'{cls.name}_{func_name}'
        else:
            # find the object having this method
            owner = list(reversed(inst.owner))
            debug(owner)
            # Use the previouse objects to find the type of the class this
            # method belongs to
            func_name = []
            scope = info.sym_tbl.current_scope
            obj = None
            for x in owner:
                obj = scope.lookup(x)
                if obj is None:
                    break
                obj_cls = obj.type.spelling
                func_name.append(obj_cls)
                scope = scope_mapping.get(f'class_{obj_cls}')
                if not scope:
                    break
            func_name.append(inst.name)
            func_name = '_'.join(func_name[-2:])
    debug('--', func_name)
    return func_name


def __get_func_imm_owner(inst, info):
    if not inst.is_method:
        return None
    obj = info.scope
    for ref_name in reversed(inst.owner):
        obj = obj.get(ref_name)
        if obj is None:
            return None
    return obj


def __get_func_args(inst, info):
    args = []
    for x in inst.cursor.get_arguments():
        arg = gather_instructions_from(x, info)
        args.extend(arg)

    # TODO: I am just sending the object as a string to be placed in the first
    # argument. Maybe I need to share a symbol object
    # If function is a method, we need to pass the reference to the object as
    # the first argument
    if inst.is_method:
        if inst.owner:
            hierarchy = []
            obj = info.scope
            for ref_name in reversed(inst.owner):
                obj = obj.get(ref_name)
                if obj is None:
                    error('Reference not found!', hierarchy, ref_name)
                    hierarchy.append(ref_name)
                    hierarchy.append('.')
                    break
                hierarchy.append(obj.name)
                if obj.is_ref:
                    hierarchy.append('->')
                else:
                    hierarchy.append('.')
            # remove the last token (. , ->)
            hierarchy.pop()
        else:
            hierarchy = ['self', '->']
        ref_name = ''.join(hierarchy)
        args = ['&'+ref_name] + args
    return args


def __add_func_definition(inst, info):
    f = Function(inst.name, inst.func_ptr)
    f.is_method = inst.is_method
    if f.is_method:
        if inst.owner:
            obj = info.scope
            for ref_name in reversed(inst.owner):
                tmp_obj = obj.get(ref_name)
                if tmp_obj is None:
                    error('Failed to find the reference!', inst.owner)
                    return
                obj = tmp_obj
            # ref_name = inst.owner[0]
            ref_state_obj = obj
            if ref_state_obj is not None:
                ref_state = ref_state_obj.clone()
                ref_state.is_ref = True
                # ref_state = f'{ref_state_obj.type} {ref_state_obj.name}'
        else:
            ref_state = 'T X'
        f.args = [ref_state] + f.args

    # Recursively analize the function body
    if f.body_cursor:
        T = inst.cursor.result_type

        # Process function body recursively
        f.body = gather_instructions_under(f.body_cursor, info)

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
    print(f'call: {inst.name} is_method: {inst.is_method}')

    # check if function is defined
    if __function_is_of_interest(inst) and inst.name not in Function.directory:
        __add_func_definition(inst, info)

    return inst

