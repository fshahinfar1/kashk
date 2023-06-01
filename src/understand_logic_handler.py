import clang.cindex as clang
from utility import (get_code, report_on_cursor, visualize_ast, get_owner,
        owner_to_ref)
from log import error, debug
from data_structure import *
from instruction import *
from understand_logic import (gather_instructions_from,
        gather_instructions_under, cb_ref)
from sym_table import *

from prune import should_process_this_file, READ_PACKET, WRITE_PACKET

from bpf_code_gen import gen_code
from template import bpf_get_data, send_response_template


COROUTINE_FUNC_NAME = ('await_resume', 'await_transform', 'await_ready', 'await_suspend')


def __function_is_of_interest(inst):
    """
    Decide if the function should also be defined in BPF code
    """
    cursor = inst.cursor
    definition = cursor.get_definition()
    if (not definition
            or not definition.location.file
            or not should_process_this_file(definition.location.file.name)):
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
    if inst.is_method:
        if len(inst.owner) == 0:
            cls = info.sym_tbl.lookup('__class__')
            func_name = f'{cls.name}_{func_name}'
        else:
            # Use the previouse objects to find the type of the class this
            # method belongs to
            owner_symb = owner_to_ref(inst.owner, info)
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
            owner_symb = owner_to_ref(inst.owner, info)
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
            hierarchy = owner_to_ref(inst.owner, info)
            if hierarchy:
                method_obj = hierarchy[-1]
                ref = f'struct {method_obj.type.spelling} *self'
            else:
                cls = scope.lookup('__class__')
                cls_text = cls.type.spelling
                method_obj = cls.ref
                ref = f'struct {cls_text} *self'
        else:
            method_obj = Object()
            method_obj.type = None
            method_obj.kind = None
            ref = 'T *self'
        f.args = [ref] + f.args
        # Add the first argument to the scope
        e = SymbolTableEntry('self', method_obj.type, method_obj.kind, method_obj)
        scope.insert(e)

    # Recursively analize the function body
    if f.body_cursor:
        # Switch scope
        old_scope = info.sym_tbl.current_scope
        info.sym_tbl.current_scope = scope

        # Add parameters to the function scope
        for a in f.args:
            if isinstance(a, str):
                error('Function argument is string not a Cursor, StateObj, ...')
            else:
                c = a.cursor
                info.sym_tbl.insert_entry(c.spelling, c.type, c.kind, c)

        # Process function body recursively
        body = gather_instructions_under(f.body_cursor, info, BODY)
        f.body.extend_inst(body) 
        info.sym_tbl.current_scope = old_scope

        info.prog.add_declaration(f)

    f.invocations.append(inst)


def understand_call_expr(c, info):
    tmp_func_name = c.spelling

    # Check if this a special type of function
    if tmp_func_name in COROUTINE_FUNC_NAME:
        # Ignore these
        return None
    elif tmp_func_name == READ_PACKET:
        # Assign packet pointer on a previouse line
        text = bpf_get_data(info.rd_buf.name)
        assign_inst = Literal(text, CODE_LITERAL)
        blk = cb_ref.get(BODY)
        blk.append(assign_inst)
        # TODO: what if `skb` is not defined in this scope?
        # Set the return value
        text = f'skb->len'
        inst = Literal(text, CODE_LITERAL)
        return inst
    elif tmp_func_name == WRITE_PACKET:
        buf = info.wr_buf.name
        write_size, _ = gen_code(info.wr_buf.write_size_cursor, info, context=ARG)
        text = send_response_template(buf, write_size)
        inst = Literal(text, CODE_LITERAL)
        return inst

    # A call to the function
    inst = Call(c)
    inst.name = __get_func_name(inst, info)
    inst.args = __get_func_args(inst, info)

    # check if function is defined
    if __function_is_of_interest(inst) and inst.name not in Function.directory:
        __add_func_definition(inst, info)

    return inst
