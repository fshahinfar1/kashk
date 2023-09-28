import clang.cindex as clang
from utility import (get_code, report_on_cursor, visualize_ast)
from log import error, debug
from prune import READ_PACKET, WRITE_PACKET
from data_structure import *
from instruction import *
from understand_logic import (gather_instructions_from,
        gather_instructions_under, cb_ref, get_global_for_bpf)
from sym_table import *

from prune import should_process_this_cursor


COROUTINE_FUNC_NAME = ('await_resume', 'await_transform', 'await_ready', 'await_suspend')
MODULE_TAG = 'LOGIC HANDLER'


def __function_is_of_interest(inst):
    """
    Decide if the function should also be defined in BPF code
    """
    cursor = inst.cursor
    definition = cursor.get_definition()
    if (not definition or not should_process_this_cursor(definition)):
        return False
    if inst.name.startswith('operator'):
        # TODO: I do not want operators for now. But It would be good to
        # support it as another function decleration and invocation
        return False
    if inst.is_method:
        # TODO: filter based on methods of types we do not want to have
        return True
        # for o in inst.owner:
        #     # TODO: i need more information from the owner not just its name
        #     if o == 'string':
        #         return False
    return True


def __get_func_name(inst, info):
    func_name = inst.cursor.spelling
    if func_name in (*READ_PACKET, *WRITE_PACKET):
        # do not rewrite the read/send functions
        return func_name
    if inst.is_method:
        if len(inst.owner) == 0:
            cls = info.sym_tbl.lookup('__class__')
            func_name = f'{cls.name}_{func_name}'
        else:
            # Use the previouse objects to find the type of the class this
            # method belongs to
            func_name = []
            for o in reversed(inst.owner):
                if o.kind == clang.CursorKind.CALL_EXPR:
                    func = o.get_function_def()
                    assert func is not None
                    func_name.append(func.return_type.spelling)
                else:
                    raise Exception(f'Unexpected type: {o.kind} {o}')
            func_name.append(inst.name)
            func_name = '_'.join(func_name[-2:])
    return func_name


def __get_func_args(inst, info):
    args = []
    for x in inst.cursor.get_arguments():
        arg = gather_instructions_from(x, info)
        args.extend(arg)

    if inst.is_method:
        if inst.owner:
            new_owner = inst.owner[1:]
            if len(new_owner) > 0:
                new_kind = clang.CursorKind.MEMBER_REF_EXPR
            else:
                new_kind = clang.CursorKind.DECL_REF_EXPR
            ref = Ref(None, new_kind)
            ref.name = inst.owner[0]
            ref.owner = new_owner
            args = [ref] + args
        else:
            # The first argument of methods are self and it is a reference
            ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
            ref.name = 'self'
            args = [ref] + args
    return args


def __add_empty_func_definition(inst, info):
    f = Function(inst.name, inst.func_ptr)
    f.is_method = inst.is_method


def __add_func_definition(inst, info):
    scope = info.sym_tbl.scope_mapping.get(inst.name)
    if not scope:
        error(MODULE_TAG, 'The scope for the function', inst.name, 'was not found')
        return
    f = Function(inst.name, inst.func_ptr)
    f.is_method = inst.is_method
    if f.is_method:
        if inst.owner:
            method_obj, _ = gen_code(inst.owner[0], info)

            T = MyType()
            T.spelling = f'struct {method_obj.type.spelling} *'
            T.kind = clang.TypeKind.POINTER
            T.under_type = MyType()
            T.under_type.spelling = f'struct {method_obj.type.spelling}'
            T.under_type.kind = clang.TypeKind.RECORD

            ref = StateObject(None)
            ref.name = 'self'
            ref.kind = clang.CursorKind.PARM_DECL
            ref.type =  T.spelling
            ref.is_pointer = True
            ref.type_ref = T
        else:
            # Use the current class as the type
            cls_sym = info.sym_tbl.lookup('__class__')

            cls_type = MyType()
            cls_type.spelling = 'struct {cls_sym.name}'
            cls_type.kind = clang.TypeKind.RECORD
            T = MyType.make_pointer(cls_type)

            ref = StateObject(None)
            ref.name = 'self'
            ref.kind = clang.CursorKind.PARM_DECL
            ref.type = T.spelling
            ref.is_pointer = True
            ref.type_ref = T

        f.args = [ref] + f.args

    # Recursively analize the function body
    c = inst.func_ptr
    body = None
    if c is not None and c.is_definition():
        children = list(c.get_children())
        body = children[-1]
        while body.kind == clang.CursorKind.UNEXPOSED_STMT:
            body = next(body.get_children())
        # assert (body.kind == clang.CursorKind.COMPOUND_STMT)
        if body.kind != clang.CursorKind.COMPOUND_STMT:
            # did not found the body
            body = None

    if body:
        # Switch scope
        old_scope = info.sym_tbl.current_scope
        info.sym_tbl.current_scope = scope

        # Add parameters to the function scope
        for a in f.args:
            info.sym_tbl.insert_entry(a.name, a.type_ref, a.kind, a)

        # Process function body recursively
        body = gather_instructions_under(body, info, BODY)
        f.body.extend_inst(body)
        info.sym_tbl.current_scope = old_scope

        info.prog.add_declaration(f)


def understand_call_expr(c, info):
    tmp_func_name = c.spelling

    # Check if this a special type of function
    if tmp_func_name in COROUTINE_FUNC_NAME:
        return None

    # A call to the function
    inst = Call(c)
    inst.name = __get_func_name(inst, info)
    inst.args = __get_func_args(inst, info)

    # check if function is defined
    if inst.name not in Function.directory:
        if get_global_for_bpf() and __function_is_of_interest(inst):
            __add_func_definition(inst, info)
        else:
            __add_func_definition(inst, info)
            # __add_empty_func_definition(inst, info)

    return inst
