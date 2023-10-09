import clang.cindex as clang
from utility import (get_code, report_on_cursor, visualize_ast, show_insts, skip_unexposed_stmt)
from log import error, debug, report
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
                elif o.kind in (clang.CursorKind.DECL_REF_EXPR, clang.CursorKind.MEMBER_REF_EXPR):
                    # Does not change the name of the function
                    continue
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
            ref = inst.owner[0]
            ref.owner = new_owner
            # TODO: ref.type is None here!
            args = [ref] + args
        else:
            # The first argument of methods are self and it is a reference
            ref = Ref(None, clang.CursorKind.DECL_REF_EXPR)
            ref.name = 'self'
            ref.type = MyType.make_pointer(MyType.make_simple('CLASS', clang.TypeKind.RECORD))
            assert False, 'The name of the class has not been set in the type FIX IT!'
            args = [ref] + args
    return args


def __add_func_definition(inst, info):
    assert False, 'Should not use this'
    if not info:
        return
    scope = info.sym_tbl.scope_mapping.get(inst.name)
    if not scope:
        if inst.is_func_ptr:
            report(f'We do not have a scope for function pointer {inst.name} but allowed the creation of Function structure! (Am I breaking assumptions?)')
            scope = None
        else:
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

    if inst.name not in Function.func_cursor:
        func_decl = c.referenced
        if not func_decl.is_definition():
            tmp = func_decl.get_definition()
            if tmp:
                func_decl = tmp
        Function.func_cursor[inst.name] = func_decl

    # check if function is defined
    # if (not inst.is_operator) and (inst.name not in Function.directory):
    #     __add_func_definition(inst, info)
    return inst


def __add_func_definition2(name, cursor, info):
    assert info is not None
    scope = info.sym_tbl.scope_mapping.get(name)
    if not scope:
        error(MODULE_TAG, 'The scope for the function', name, 'was not found')
        return

    f = Function(name, cursor)
    is_operator = name.startswith('operator')
    is_method = False
    fn_def = cursor.get_definition()
    if not is_operator and fn_def and fn_def.kind == clang.CursorKind.CXX_METHOD:
        is_method = True
    f.is_method = is_method

    if f.is_method:
        raise Exception('Re implement passing the class object to the function')

    # Recursively analize the function body
    body = None
    if fn_def:
        children = list(fn_def.get_children())
        body = children[-1]
        body = skip_unexposed_stmt(body)
        if body.kind != clang.CursorKind.COMPOUND_STMT:
            # did not found the body
            error(f'Did not found the body for function: {f.name}')
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


def create_func_objs(info):
    processed = set()
    while True:
        keys = set(Function.func_cursor.keys())
        if keys == processed:
            break
        for name in keys:
            if name in processed:
                continue
            cursor = Function.func_cursor[name]
            __add_func_definition2(name, cursor, info)
        processed.update(keys)
