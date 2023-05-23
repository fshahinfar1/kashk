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


def __owner_to_ref(owner, info):
    owner = reversed(owner)
    hierarchy = []
    scope = info.sym_tbl.current_scope
    obj = None
    for x in owner:
        obj = scope.lookup(x)
        if obj is None:
            break
        hierarchy.append(obj)
        obj_cls = obj.type.spelling
        scope = scope_mapping.get(f'class_{obj_cls}')
        if not scope:
            break
    return hierarchy


def __get_func_name(inst, info):
    func_name = inst.cursor.spelling
    if inst.is_method:
        if len(inst.owner) == 0:
            cls = info.sym_tbl.lookup('__class__')
            # debug(cls)
            func_name = f'{cls.name}_{func_name}'
        else:
            # Use the previouse objects to find the type of the class this
            # method belongs to
            owner_symb = __owner_to_ref(inst.owner, info)
            func_name = list(map(lambda obj: obj.type.spelling, owner_symb))
            func_name.append(inst.name)
            func_name = '_'.join(func_name[-2:])
    return func_name


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
            owner_symb = __owner_to_ref(inst.owner, info)
            if owner_symb:
                for obj in owner_symb:
                    hierarchy.append(obj.name)
                    link = '->' if obj.is_pointer else '.'
                    hierarchy.append(link)
                hierarchy.pop()
            else:
                error('owner list is not empty but we did not found the symbols')
            ref_name = ''.join(hierarchy)
            args = ['&'+ref_name] + args
        else:
            # The first argument of methods are self and it is a reference
            args = ['self'] + args
    return args


def __add_func_definition(inst, info):
    scope = scope_mapping.get(inst.name)
    if not scope:
        error('The scope for the function', inst.name, 'was not found')
        return
    f = Function(inst.name, inst.func_ptr)
    f.is_method = inst.is_method
    if f.is_method:
        if inst.owner:
            owner_symb = __owner_to_ref(inst.owner, info)
            if owner_symb:
                ref = f'struct {owner_symb[-1].type.spelling} *self'
            else:
                cls = scope.lookup('__class__')
                cls_text = cls.type.spelling
                ref = f'struct {cls_text} *self'
        else:
            ref = 'T *self'
        f.args = [ref] + f.args

    # Recursively analize the function body
    if f.body_cursor:
        T = inst.cursor.result_type

        old_scope = info.sym_tbl.current_scope
        info.sym_tbl.current_scope = scope
        # Process function body recursively
        f.body = gather_instructions_under(f.body_cursor, info)
        info.sym_tbl.current_scope = old_scope

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

