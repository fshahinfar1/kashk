import clang.cindex as clang

from data_structure import Function, StateObject

READ_PACKET = 'async_read_some'
WRITE_PACKET = 'async_write'
INDENT = '  '

is_first_time = True
def call_read_packet(inst, info, more):
    global is_first_time
    lvl = more[0]
    if not is_first_time:
        return ''
    is_first_time = False
    return INDENT * lvl + f'{info.rd_buf.name} = (void *)(__u64)skb->data'


def handle_var(inst, info, more):
    lvl = more[0]
    text = INDENT * lvl + f'{inst.type} {inst.name}'
    if inst.init:
        init_text = gen_code(inst.init, info, context=RHS)
        text += ' = ' + init_text
    return text


def handle_call(inst, info, more):
    if inst.name == READ_PACKET:
        return call_read_packet(inst, info, more)

    lvl = more[0]
    func_name = '__this_function_name_is_not_defined__'
    args = list(inst.args) # a copy of the objects list of argument
    if inst.is_method:
        # find the object having this method
        owners = list(reversed(inst.owner))
        func_name = []
        obj = info.scope
        for x in owners:
            obj = obj.get(x)
            if obj is None:
                break
            func_name.append(obj.type)
            if not obj:
                raise Exception(f'Object not found: {obj}')
        func_name.append(inst.name)
        func_name = '_'.join(func_name)
        args = [obj] + args
    else:
        func_name = inst.name

    # check if function is defined
    if func_name not in Function.directory:
        f = Function(func_name, inst.func_ptr)
        info.prog.add_declaration(f)
        # TODO: generate the definition of the function
    else:
        f = Function.directory[func_name]
        info.prog.add_declaration(f)

    args_text = ', '.join([gen_code([x], info, context=ARG) for x in args])

    # TODO: only generate ; if it is not as an argument
    text = INDENT * lvl + func_name + '(' + args_text + ')'
    return text


def handle_bin_op(inst, info, more):
    lvl = more[0]
    lhs = gen_code(inst.lhs, info, context=LHS)
    rhs = gen_code(inst.rhs, info, context=RHS)
    text = INDENT * lvl + lhs + ' ' +  inst.op + ' '+ rhs
    return text


def handle_ref_expr(inst, info, more):
    lvl = more[0]
    state_obj = info.scope.get(inst.name)
    if state_obj:
        text = __generate_code_ref_state_obj(state_obj)
    else:
        text = inst.name
    return text


def handle_literal(inst, info, more):
    lvl = more[0]
    return INDENT * lvl + inst.text


def handle_if_stmt(inst, info, more):
    lvl = more[0]

    body = gen_code(inst.body, info, context=BODY).split('\n')
    indented = []
    for b in body:
        indented.append(INDENT * (lvl + 1) + b)
    body = '\n'.join(indented)
        
    text = f'if ({inst.cond}) {{\n' + body + '}'
    if inst.other_body:
        body = gen_code(inst.other_body, info, context=BODY).split('\n')
        indented = []
        for b in body:
            indented.append(INDENT * (lvl + 1) + b)
        body = '\n'.join(indented)
        text += 'else {\n' + body + '}'
    return text


def handle_do_stmt(inst, info, more):
    lvl = more[0]
    body = gen_code(inst.body, info, context=BODY).split('\n')
    indented = []
    for b in body:
        indented.append(INDENT * (lvl + 1) + b)
    body = '\n'.join(indented)
    text = 'do {\n' + body + f'\n}} while ({inst.cond})'
    return text


def load_connection_state():
    return '''
if (skb->sk == NULL) {
  bpf_printk("The socket reference is NULL");
  return SK_DROP;
}
sock_ctx = bpf_sk_storage_get(&sock_ctx_map, skb->sk, NULL, 0);
if (!sock_ctx) {
  bpf_printk("Failed to get socket context!");
  return SK_DROP;
}
'''



BODY = 0
ARG = 1
LHS = 2
RHS = 3

NEED_SEMI_COLON = (clang.CursorKind.CALL_EXPR, clang.CursorKind.VAR_DECL, clang.CursorKind.BINARY_OPERATOR, clang.CursorKind.CONTINUE_STMT, clang.CursorKind.DO_STMT)
GOTO_NEXT_LINE = (clang.CursorKind.IF_STMT,)

def gen_program(list_instructions, info):
    code = load_connection_state()
    code += gen_code(list_instructions, info)
    return code

def gen_code(list_instructions, info, context=BODY):
    jump_table = {
            clang.CursorKind.CALL_EXPR: handle_call,
            clang.CursorKind.VAR_DECL: handle_var,
            clang.CursorKind.BINARY_OPERATOR: handle_bin_op,
            clang.CursorKind.DECL_REF_EXPR: handle_ref_expr,
            clang.CursorKind.INTEGER_LITERAL: handle_literal,
            clang.CursorKind.FLOATING_LITERAL: handle_literal,
            clang.CursorKind.CXX_BOOL_LITERAL_EXPR: handle_literal,
            clang.CursorKind.IF_STMT: handle_if_stmt,
            clang.CursorKind.DO_STMT: handle_do_stmt,
            clang.CursorKind.CONTINUE_STMT: lambda x,y,z: 'continue',
            }
    count = len(list_instructions)
    q = reversed(list_instructions)
    q = list(zip(q, [0] * count))
    code = ''
    while q:
        inst, lvl = q.pop()

        if inst is None:
            text = '<missing something>'
        elif isinstance(inst, StateObject):
            # TODO: this is bad code design, remove this branch
            text = __generate_code_ref_state_obj(inst)
        else:
            handler = jump_table.get(inst.kind, lambda x,y,z: '')
            text = handler(inst, info, [lvl])
        
        if not text:
            text = f'<empty code generated kind: {inst.kind}>'

        if context == BODY:
            if inst.kind in NEED_SEMI_COLON:
                text += ';\n'
            elif inst.kind in GOTO_NEXT_LINE:
                text += '\n'


        code += text
    return code


def __generate_code_ref_state_obj(state_obj):
    # print(state_obj, state_obj.parent_object)
    hierarchy, g = __build_hierarchy(state_obj)
    hierarchy = '.'.join([h.name for h in reversed(hierarchy)])
    if g:
        text = 'sock_ctx->' + hierarchy
    else:
        text = hierarchy
    return text

def __build_hierarchy(state_obj):
    g = False
    hierarchy = [state_obj]
    x = state_obj
    while x.parent_object is not None:
        hierarchy.append(x.parent_object)
        x = x.parent_object
    if hierarchy[-1].is_global:
        g  = True
    return hierarchy, g
