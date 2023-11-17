import clang.cindex as clang
from utility import (get_code, report_on_cursor, visualize_ast, skip_unexposed_stmt)
from log import error, debug, report
from prune import READ_PACKET, WRITE_PACKET, COROUTINE_FUNC_NAME
from data_structure import *
from instruction import *
from understand_logic import gather_instructions_from, gather_instructions_under
from sym_table import *

from prune import should_process_this_cursor


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


# def _remember_func_cursor(inst, c):
#     # TODO: I should have noticed all the functions I need in the symbol table generation
#     # should I not?
#     return
#     if inst.is_operator:
#         return
#     # Remember the function definition cursor for later generating the Function
#     # data structure
#     know_previous_def_of_func = False
#     if inst.name in Function.func_cursor:
#         func_def_cursor = Function.func_cursor[inst.name]
#         know_previous_def_of_func = func_def_cursor.is_definition()
#     func_decl = c.referenced
#     assert func_decl is not None, 'Failed to parse: did not found the cursor to the function decleration/definition'
#     if not func_decl.is_definition():
#         tmp = func_decl.get_definition()
#         if tmp:
#             func_decl = tmp
#     if know_previous_def_of_func:
#         if func_decl.is_definition():
#             if func_decl == func_def_cursor:
#                 # This is the same definition we already know about
#                 pass
#             else:
#                 error(MODULE_TAG, f'Multiple definition for function {inst.name} is found!')
#         else:
#             # We already know a definition and do not care about this cursor.
#             pass
#     else:
#         Function.func_cursor[inst.name] = func_decl


def understand_call_expr(c, info):
    tmp_func_name = c.spelling

    # Check if this a special type of function
    if tmp_func_name in COROUTINE_FUNC_NAME:
        return None

    # A call to the function
    inst = Call(c)
    inst.name = __get_func_name(inst, info)
    inst.args = __get_func_args(inst, info)

    # _remember_func_cursor(inst, c)
    return inst


def __add_func_definition2(name, cursor, info):
    assert info is not None

    f = Function(name, cursor)
    is_operator = name.startswith('operator')
    is_method = False
    fn_def = cursor.get_definition()
    if not is_operator and fn_def and fn_def.kind == clang.CursorKind.CXX_METHOD:
        is_method = True
    f.is_method = is_method
    f.is_operator = is_operator

    if is_operator:
        # I am not messing up with operators now
        return

    if f.is_method:
        raise Exception('Re implement passing the class object to the function')

    scope = info.sym_tbl.scope_mapping.get(name)
    if scope is not None:
        # Add parameters to the function scope
        for a in f.args:
            scope.insert_entry(a.name, a.type_ref, a.kind, a)

    # Recursively analize the function body
    body = None
    if fn_def:
        children = list(fn_def.get_children())
        body = children[-1]
        body = skip_unexposed_stmt(body)
        if body.kind != clang.CursorKind.COMPOUND_STMT:
            # did not found the body
            # error(f'Did not found the body for function: {f.name}')
            body = None

    if body and scope is not None and should_process_this_cursor(cursor):
        # NOTE: The irrelevant functions does not need to have body :)
        # This function has body but let's not evaluate it. (Lazy evaluation)
        ev = FunctionBodyEvaluator(body, info, f)
        f.body = ev


def create_func_objs(info):
    # processed = set([info.io_ctx.entry_func, ])
    processed = set()
    while True:
        keys = set(Function.func_cursor.keys())
        # if keys == processed:
        #     break
        if len(processed) >= len(keys):
            break
        # print(len(processed), '/', len(keys))
        for name in keys:
            if name in processed:
                continue
            cursor = Function.func_cursor[name]
            __add_func_definition2(name, cursor, info)
        processed.update(keys)


def _declare_func(info, name, args, return_type, code):
    assert isinstance(args, list)
    assert isinstance(return_type, MyType)
    assert isinstance(code, str)
    func = Function(name, None)
    func.is_operator = False
    func.is_method = False
    func.args = args
    func.return_type = return_type
    func.may_succeed = True
    scope = Scope(info.sym_tbl.global_scope)
    info.sym_tbl.scope_mapping[name] = scope
    for a in func.args:
        scope.insert_entry(a.name, a.type_ref, a.kind, None)
    func.body.add_inst(Literal(code, CODE_LITERAL))
    return func


def add_known_func_objs(info):
    # STRLEN
    func_name = 'bpf_strlen'
    count_args = 1
    args = [StateObject(None) for i in range(count_args)]
    args[0].name = 'str'
    args[0].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
    return_type = BASE_TYPES[clang.TypeKind.UINT]
    code = '''
int len;
len = 0;
int i;
for(i = 0; i < 256; (i)++) {
if (str[i] == '\\0') {
  return (len);
}
(len)++;
}
return ((unsigned int)(-(1)));
'''
    _declare_func(info, func_name, args, return_type, code)

    # STRNCPY
    func_name = 'bpf_strncpy'
    count_args = 4
    args = [StateObject(None) for i in range(count_args)]
    args[0].name = 'dest'
    args[0].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
    args[1].name = 'src'
    args[1].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
    args[2].name = 'n'
    args[2].type_ref = BASE_TYPES[clang.TypeKind.UINT]
    args[3].name = 'end_dest'
    args[3].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
    # args[4].name = 'end_src'
    # args[4].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
    return_type = BASE_TYPES[clang.TypeKind.VOID]
    code = '''
if (n == 0) return;
for (unsigned short i = 0; i < 256; i++) {
  if ((void *)(dest + i + 1) > end_dest) break;
  dest[i] = src[i];
  if (src[i] == '\\0' || i >= n - 1) {
    break;
  }
}
'''
    _declare_func(info, func_name, args, return_type, code)

    # STRNCMP
    func_name = 'bpf_strncmp'
    count_args = 3
    args = [StateObject(None) for i in range(count_args)]
    args[0].name = 'str1'
    args[0].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
    args[1].name = 'str2'
    args[1].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
    args[2].name = 'len'
    args[2].type_ref = BASE_TYPES[clang.TypeKind.USHORT]
    return_type = BASE_TYPES[clang.TypeKind.INT]
    code = '''
int i;
for(i = 0; i < 256; (i)++) {
  if (i == len) {
    return (0);
  }
  if (str1[i] != str2[i] || str1[i] == '\\0') {
    return (str1[i] - str2[i]);
  }
}
return (-(10000));
'''
    _declare_func(info, func_name, args, return_type, code)

    # FNV_HASH
    func_name = '__fnv_hash'
    count_args = 2
    args = [StateObject(None) for i in range(count_args)]
    args[0].name = 'key'
    args[0].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
    args[1].name = 'size'
    args[1].type_ref = BASE_TYPES[clang.TypeKind.INT]
    return_type = BASE_TYPES[clang.TypeKind.INT]
    code = '''
return 0;
'''
    _declare_func(info, func_name, args, return_type, code)

    # MEMCPY
    func_name = 'bpf_memcpy'
    count_args = 5
    args = [StateObject(None) for i in range(count_args)]
    args[0].name = 'dest'
    args[0].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
    args[1].name = 'src'
    args[1].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.SCHAR])
    args[2].name = 'n'
    args[2].type_ref = BASE_TYPES[clang.TypeKind.USHORT]
    args[3].name = 'end_dest'
    args[3].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
    args[4].name = 'end_src'
    args[4].type_ref = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
    return_type = BASE_TYPES[clang.TypeKind.VOID]
    code = '''
if (n == 0) return;
for (unsigned short i = 0; i < 256; i++) {
  if ((void *)(dest + i + 1) > end_dest) break;
  if ((void *)(src  + i + 1) > end_src ) break;
  dest[i] = src[i];
  if (i >= n - 1) {
    break;
  }
}
'''
    _declare_func(info, func_name, args, return_type, code)
