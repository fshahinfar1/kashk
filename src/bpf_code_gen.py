import clang.cindex as clang

from data_structure import *
from utility import indent, INDENT, report_on_cursor

READ_PACKET = 'async_read_some'
WRITE_PACKET = 'async_write'

is_first_time = True
def call_read_packet(inst, info, more):
    # TODO: update the variable receiving the return value (read length)
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
        init_text, _ = gen_code(inst.init, info, context=RHS)
        text += ' = ' + init_text
    return text


def handle_call(inst, info, more):
    lvl = more[0]
    func_name = inst.name
    args = list(inst.args) # a copy of the objects list of argument
    code_args = []
    for x in args:
        tmp, _ = gen_code([x], info, context=ARG)
        code_args.append(tmp)
    args_text = ', '.join(code_args)

    # TODO: only generate ; if it is not as an argument
    text = INDENT * lvl + func_name + '(' + args_text + ')'
    return text


def handle_bin_op(inst, info, more):
    lvl = more[0]
    lhs, _ = gen_code(inst.lhs, info, context=LHS)
    rhs, m = gen_code(inst.rhs, info, context=RHS)
    
    if m == REPLACE_READ:
        text = ((INDENT * lvl) + rhs + ';\n' 
        + (INDENT * lvl) + lhs + ' ' + inst.op + ' ' + '((__u64)skb->data_end - (__u64)skb->data)')
    else:
        text = INDENT * lvl + lhs + ' ' +  inst.op + ' '+ rhs
    return text


def handle_unary_op(inst, info, more):
    lvl = more[0]
    child, _ = gen_code(inst.child, info, context=ARG)
    text = f'{inst.op}({child})'
    return text


def handle_ref_expr(inst, info, more):
    lvl = more[0]
    state_obj = info.scope.get(inst.name)
    if state_obj:
        text = __generate_code_ref_state_obj(state_obj)
    else:
        text = inst.name
    return text


def handle_member_ref_expr(inst, info, more):
    lvl = more[0]
    # TODO: ...
    assert len(inst.owner) == 0
    print(inst.name)
    assert info.context.kind == ContextInfo.KindFunction
    # reference to the object will be in the first argument of the function
    args = info.context.ref.args
    if len(args) < 1:
        return '<missing ref>->{inst.name}'
    obj = args[0]
    if isinstance(obj, str):
        # TODO: this probably was a method call and the first arguement is the
        # reference to the object.
        text = f'{obj}->{inst.name}'
    else:
        text = f'{obj.name}->{inst.name}'
    return text


def handle_literal(inst, info, more):
    lvl = more[0]
    return INDENT * lvl + inst.text


def handle_if_stmt(inst, info, more):
    lvl = more[0]

    body, _ = gen_code(inst.body, info, context=BODY)
    body = indent(body, 1)
    cond, _ = gen_code(inst.cond, info, context=ARG)
    text = f'if ({cond}) {{\n' + body + '\n}'
    if inst.other_body:
        body, _ = gen_code(inst.other_body, info, context=BODY)
        body = indent(body, 1)
        text += 'else {\n' + body + '\n}'
    return text


def handle_do_stmt(inst, info, more):
    lvl = more[0]
    body, _ = gen_code(inst.body, info, context=BODY)
    body = body.split('\n')
    indented = []
    for b in body:
        indented.append(INDENT * (lvl + 1) + b)
    body = '\n'.join(indented)
    cond, _ = gen_code(inst.cond, info, context=ARG)
    text = 'do {\n' + body + f'\n}} while ({cond})'
    return text


BODY = 0
ARG = 1
LHS = 2
RHS = 3
DEF = 4

NEED_SEMI_COLON = set((clang.CursorKind.CALL_EXPR, clang.CursorKind.VAR_DECL,
    clang.CursorKind.BINARY_OPERATOR, clang.CursorKind.CONTINUE_STMT,
    clang.CursorKind.DO_STMT, clang.CursorKind.RETURN_STMT,
    clang.CursorKind.CONTINUE_STMT, clang.CursorKind.CXX_THROW_EXPR,))
GOTO_NEXT_LINE = (clang.CursorKind.IF_STMT,)

NO_MODIFICATION = 0
REPLACE_READ = 1
CHANGE_BUFFER_DEF = 2

def gen_code(list_instructions, info, context=BODY):
    jump_table = {
            clang.CursorKind.CALL_EXPR: handle_call,
            clang.CursorKind.BINARY_OPERATOR: handle_bin_op,
            clang.CursorKind.UNARY_OPERATOR: handle_unary_op,
            clang.CursorKind.VAR_DECL: handle_var,
            clang.CursorKind.DECL_REF_EXPR: handle_ref_expr,
            clang.CursorKind.MEMBER_REF_EXPR: handle_member_ref_expr,
            clang.CursorKind.INTEGER_LITERAL: handle_literal,
            clang.CursorKind.FLOATING_LITERAL: handle_literal,
            clang.CursorKind.CXX_BOOL_LITERAL_EXPR: handle_literal,
            clang.CursorKind.IF_STMT: handle_if_stmt,
            clang.CursorKind.DO_STMT: handle_do_stmt,
            clang.CursorKind.CONTINUE_STMT: lambda x,y,z: 'continue',
            clang.CursorKind.RETURN_STMT: lambda x,y,z: 'return SK_DROP',
            clang.CursorKind.CXX_THROW_EXPR: lambda x,y,z: 'return SK_DROP',
            }
    count = len(list_instructions)
    q = reversed(list_instructions)
    q = list(zip(q, [0] * count))
    code = ''
    modified = NO_MODIFICATION
    while q:
        inst, lvl = q.pop()

        if inst is None:
            text = '<missing something>'
        elif isinstance(inst, StateObject):
            # TODO: this is bad code design, remove this branch
            text = __generate_code_ref_state_obj(inst)
        elif isinstance(inst, TypeDefinition):
            text = __generate_code_type_definition(inst, info)
            if not text:
                # We do not want this definition
                continue
        else:
            # Some special rules
            if inst.kind == clang.CursorKind.VAR_DECL and inst.name == info.rd_buf.name:
                text = f'char *{info.rd_buf.name}'
                modified = CHANGE_BUFFER_DEF
            elif inst.kind == clang.CursorKind.CALL_EXPR and inst.name == 'operator<<':
                text = f'// removing a call to "<<" operator'
                modified = CHANGE_BUFFER_DEF
            elif inst.kind == clang.CursorKind.CALL_EXPR and inst.name == READ_PACKET:
                text = call_read_packet(inst, info, [lvl])
                modified = REPLACE_READ
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
        elif context == DEF:
            text += ';\n'


        code += text
    return code, modified


def generate_bpf_prog(info):
    decs = list(info.prog.declarations)
    declarations, _ = gen_code(decs, info, context=DEF) 
    parser_code, _ = gen_code(info.prog.parser_code, info)
    parser_code = indent(parser_code, 1)

    code = ([]
            + info.prog.headers
            + [declarations]
            + info.prog._per_connection_state()
            + info.prog._parser_prog([parser_code])
            + info.prog._verdict_prog([])
            + [f'char _license[] SEC("license") = "{info.prog.license}";',]
            )
    return '\n'.join(code)


def __generate_code_type_definition(inst, info):
    if isinstance(inst, Function):
        if inst.cursor.spelling in (READ_PACKET, WRITE_PACKET):
            return ''

        # Change the context
        old_ctx = info.context 
        new_ctx = ContextInfo(ContextInfo.KindFunction, inst)
        info.context = new_ctx
        body, _ = gen_code(inst.body, info)
        # Switch back the context
        info.context = old_ctx

        body = indent(body)

        text = f'{inst.return_type} {inst.name} ({inst.args}) {{\n{body}\n}}'
        return text
    else:
        return inst.get_c_code()


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
