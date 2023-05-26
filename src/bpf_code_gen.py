import clang.cindex as clang

from data_structure import *
from utility import (indent, INDENT, report_on_cursor, owner_to_ref)
from sym_table import scope_mapping
from prune import READ_PACKET, WRITE_PACKET


def check_if_shared_obj_is_loaded(info):
    shared_sym = info.sym_tbl.lookup('shared')
    if shared_sym:
        # This object is defined in this scope
        return False, ''
    text = '''
struct shared_state *shared = NULL;
{
  int zero = 0;
  shared = bpf_map_lookup_elem(&shared_map, &zero);
}
'''
    return True, text

def only_once(f):
    is_first_time = True
    def x(*args, **kwargs):
        if not is_first_time:
            return ''
        is_first_time = False
        return f(*args, **kwargs)
    return x

is_first_time_1 = True
def call_read_packet(inst, info, more):
    global is_first_time_1
    lvl = more[0]
    if not is_first_time_1:
        return ''
    is_first_time_1 = False
    return indent(f'{info.rd_buf.name} = (void *)(__u64)skb->data', lvl)


is_first_time_2 = True
def call_send_packet(inst, info, more):
    global is_first_time_2
    lvl = more[0]
    if not is_first_time_2:
        return ''
    is_first_time_2 = False

    buf = info.wr_buf.name
    write_size, _ = gen_code(info.wr_buf.write_size_cursor, info, context=ARG)
    code = [
        f'__adjust_skb_size(skb, {write_size});',
        f'if (((void *)(__u64)skb->data + {write_size})  > (void *)(__u64)skb->data_end) {{',
        f'  return SK_DROP;',
        '}',
        f'memcpy((void *)(__u64)skb->data, {buf}, {write_size});',
        'return bpf_sk_redirect_map(skb, &sock_map, sock_ctx->sock_map_index, 0);',
        ]
    text = '\n'.join(code)
    text = indent(text, lvl)
    return text


def handle_var(inst, info, more):
    lvl = more[0]
    if inst.is_array:
        el_type = inst.cursor.type.element_type.spelling
        el_count = inst.cursor.type.element_count
        text = f'{el_type} {inst.name}[{el_count}]'
    elif inst.cursor.type.kind == clang.TypeKind.RECORD:
        text = f'struct {inst.type} {inst.name}'
    else:
        text = f'{inst.type} {inst.name}'
    if inst.init:
        init_text, _ = gen_code(inst.init, info, context=RHS)
        text += ' = ' + init_text
    indent(text, lvl)
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
    text = indent(func_name + '(' + args_text + ')', lvl)
    return text


def handle_bin_op(inst, info, more):
    lvl = more[0]
    lhs, _ = gen_code(inst.lhs, info, context=LHS)
    rhs, m = gen_code(inst.rhs, info, context=RHS)

    if m == REPLACE_READ:
        text = (rhs + ';\n' + lhs + ' ' + inst.op + ' ' +
                '((__u64)skb->data_end - (__u64)skb->data)')
    else:
        text = f'{lhs} {inst.op} {rhs}'
    text = indent(text, lvl)
    return text


def handle_unary_op(inst, info, more):
    lvl = more[0]
    child, _ = gen_code(inst.child, info, context=ARG)
    text = f'{inst.op}({child})'
    return text


def handle_ref_expr(inst, info, more):
    lvl = more[0]
    # Check if the variable is shared globally or per_connection.
    sym, scope = info.sym_tbl.lookup2(inst.name)
    is_global = scope == info.sym_tbl.global_scope
    is_shared = scope == info.sym_tbl.shared_scope
    if is_global:
        text = 'sock_ctx->state.' + inst.name
    elif is_shared:
        # TODO: WHERE SHOULD I PUT THESE CODE? IT SHOULD BE ON SOME PART OF THE
        # FUNCTION BODY BEFORE REACHING THIS STATEMENT.
        # res, definition = check_if_shared_obj_is_loaded(info)
        # if res:
        #     text = definition + '\n' + text

        text = 'shared->' + inst.name
    else:
        text = inst.name
    text = indent(text, lvl)

    return text


def handle_member_ref_expr(inst, info, more):

    lvl = more[0]
    if len(inst.owner) == 0:
        # Access to the members of this class
        text = f'self->{inst.name}'
    else:
        # This object is not for this class
        hierarchy = owner_to_ref(inst.owner, info)
        links = []
        for obj in hierarchy:
            links.append(obj.name)
            link = '->' if obj.is_pointer else '.'
            links.append(link)
        links.append(inst.name)
        text = ''.join(links)

    text = indent(text, lvl)
    return text

def handle_array_sub(inst, info, more):
    lvl = more[0]
    name, _ = gen_code(inst.array_ref, info, context=ARG)
    index, _ = gen_code(inst.index, info, context=ARG)
    text = f'{name}[{index}]'
    text = indent(text, lvl)
    return text


def handle_cast_expr(inst, info, more):
    lvl = more[0]
    body, _ = gen_code(inst.castee, info, context=ARG)
    if isinstance(inst.cast_type, str):
        ctype = inst.cast_type
    else:
        ctype = inst.cast_type.spelling
        if inst.cast_type.kind == clang.TypeKind.POINTER:
            ctype += ' *'
    text = f'({ctype})({body})'
    text = indent(text, lvl)
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
        text += ' else {\n' + body + '\n}'
    text = indent(text, lvl)
    return text


def handle_do_stmt(inst, info, more):
    lvl = more[0]
    cond, _ = gen_code(inst.cond, info, context=ARG)
    body, _ = gen_code(inst.body, info, context=BODY)
    body = indent(body, 1)
    text = 'do {\n' + body + f'\n}} while ({cond})'
    text = indent(text, lvl)
    return text


def handle_for_stmt(inst, info,more):
    lvl = more[0]
    pre, _  =  gen_code(inst.pre, info, context=ARG)
    cond, _ = gen_code(inst.cond, info, context=ARG)
    post, _ = gen_code(inst.post, info, context=ARG)
    body, _ = gen_code(inst.body, info, context=BODY)
    body = indent(body)
    text = f'for({pre}; {cond}; {post}) {{\n{body}\n}}'
    text = indent(text, lvl)
    return text


def handle_switch_stmt(inst, info, more):
    lvl = more[0]
    cond, _ = gen_code(inst.cond, info, context=ARG)
    body, _ = gen_code(inst.body, info, context=BODY)
    body = indent(body)
    text = f'switch ({cond}) {{\n{body}\n}}'
    text = indent(text, lvl)
    return text


def handle_case_stmt(inst, info, more):
    lvl = more[0]
    case, _ = gen_code(inst.case, info, context=ARG)
    body, _ = gen_code(inst.body, info, context=BODY)
    body = indent(body)
    text = f'case ({case}):\n{body}\n'
    text = indent(text, lvl)
    return text


def handle_default_stmt(inst, info, more):
    lvl = more[0]
    body, _ = gen_code(inst.body, info, context=BODY)
    body = indent(body)
    text = f'default:\n{body}'
    text = indent(text, lvl)
    return text


def handle_conditional_op(inst, info, more):
    lvl = more[0]
    cond, _ = gen_code(inst.cond, info, context=ARG)
    body, _ = gen_code(inst.body, info, context=BODY)
    other_body, _ = gen_code(inst.other_body, info, context=BODY)
    text = f'({cond}) ? ({body}) : ({other_body})'
    text = indent(text, lvl)
    return text


def handle_paren_expr(inst, info, more):
    lvl = more[0]
    body, _ = gen_code(inst.body, info, context=ARG)
    text = f'({body})'
    text = indent(text, lvl)
    return text


def handle_return_stmt(inst, info, more):
    lvl = more[0]
    body, _ = gen_code(inst.body, info, context=ARG)
    text = f'return ({body})'
    text = indent(text, lvl)
    return text


BODY = 0
ARG = 1
LHS = 2
RHS = 3
DEF = 4

NEED_SEMI_COLON = set((clang.CursorKind.CALL_EXPR, clang.CursorKind.VAR_DECL,
    clang.CursorKind.BINARY_OPERATOR, clang.CursorKind.CONTINUE_STMT,
    clang.CursorKind.DO_STMT, clang.CursorKind.RETURN_STMT,
    clang.CursorKind.CONTINUE_STMT, clang.CursorKind.BREAK_STMT, clang.CursorKind.CXX_THROW_EXPR,))
GOTO_NEXT_LINE = (clang.CursorKind.IF_STMT,)

NO_MODIFICATION = 0
REPLACE_READ = 1
CHANGE_BUFFER_DEF = 2


def gen_code(list_instructions, info, context=BODY):
    jump_table = {
            clang.CursorKind.CALL_EXPR: handle_call,
            clang.CursorKind.BINARY_OPERATOR: handle_bin_op,
            clang.CursorKind.UNARY_OPERATOR: handle_unary_op,
            # Vars
            clang.CursorKind.VAR_DECL: handle_var,
            clang.CursorKind.DECL_REF_EXPR: handle_ref_expr,
            clang.CursorKind.MEMBER_REF_EXPR: handle_member_ref_expr,
            clang.CursorKind.ARRAY_SUBSCRIPT_EXPR: handle_array_sub,
            clang.CursorKind.CSTYLE_CAST_EXPR: handle_cast_expr,
            # Literals
            clang.CursorKind.INTEGER_LITERAL: handle_literal,
            clang.CursorKind.FLOATING_LITERAL: handle_literal,
            clang.CursorKind.CHARACTER_LITERAL: handle_literal,
            clang.CursorKind.STRING_LITERAL: handle_literal,
            clang.CursorKind.CXX_BOOL_LITERAL_EXPR: handle_literal,
            # Control FLow
            clang.CursorKind.IF_STMT: handle_if_stmt,
            clang.CursorKind.DO_STMT: handle_do_stmt,
            clang.CursorKind.FOR_STMT: handle_for_stmt,
            clang.CursorKind.SWITCH_STMT: handle_switch_stmt,
            clang.CursorKind.CASE_STMT: handle_case_stmt,
            clang.CursorKind.DEFAULT_STMT: handle_default_stmt,
            clang.CursorKind.CONDITIONAL_OPERATOR: handle_conditional_op,
            #
            clang.CursorKind.PAREN_EXPR: handle_paren_expr,
            #
            clang.CursorKind.BREAK_STMT: lambda x,y,z: 'break',
            clang.CursorKind.CONTINUE_STMT: lambda x,y,z: 'continue',
            clang.CursorKind.RETURN_STMT: handle_return_stmt,
            clang.CursorKind.CXX_THROW_EXPR: lambda x,y,z: 'return SK_DROP',
            }
    count = len(list_instructions)
    q = reversed(list_instructions)
    q = list(zip(q, [0] * count))
    code = []
    modified = NO_MODIFICATION
    while q:
        inst, lvl = q.pop()

        if inst is None:
            text = '<missing something>'
        elif isinstance(inst, str):
            text = inst
        elif isinstance(inst, StateObject):
            # TODO: this is bad code design, remove this branch
            text = handle_ref_expr(inst, info, [lvl])
        elif isinstance(inst, TypeDefinition):
            text = __generate_code_type_definition(inst, info)
            if not text:
                # We do not want this definition
                continue
        else:
            # Some special rules
            if (inst.kind == clang.CursorKind.VAR_DECL
                    and inst.name in (info.rd_buf.name,)): #  info.wr_buf.name
                if inst.name == info.rd_buf.name:
                    text = f'char *{info.rd_buf.name}'
                    modified = CHANGE_BUFFER_DEF
                # elif inst.name == info.wr_buf.name:
                #     text = ''
                #     modified = CHANGE_BUFFER_DEF
            elif inst.kind == clang.CursorKind.CALL_EXPR and inst.name == 'operator<<':
                text = f'// removing a call to "<<" operator'
                modified = CHANGE_BUFFER_DEF
            elif inst.kind == clang.CursorKind.CALL_EXPR and inst.cursor.spelling == READ_PACKET:
                text = call_read_packet(inst, info, [lvl])
                modified = REPLACE_READ
            elif inst.kind == clang.CursorKind.CALL_EXPR and inst.cursor.spelling == WRITE_PACKET:
                text = call_send_packet(inst, info, [lvl])
                modified = REPLACE_READ
            else:
                handler = jump_table.get(inst.kind, lambda x,y,z: '')
                text = handler(inst, info, [lvl])

            if not text:
                text = f'<empty code generated kind: {inst.kind}>'
                debug('<empty code>: ', inst, inst.kind)

        if context == BODY:
            if inst.kind in NEED_SEMI_COLON:
                text += ';\n'
            elif inst.kind in GOTO_NEXT_LINE:
                text += '\n'
        elif context == DEF:
            text += ';\n'


        code.append(text)
    text = ''.join(code)
    return text, modified


def generate_bpf_prog(info):
    fields = []
    for x in info.sym_tbl.shared_scope.symbols.values():
        o = StateObject(x.ref)
        fields.append(o)
    shared_state = Record('shared_state', fields)


    decs = list(info.prog.declarations)
    non_func_decs = list(filter(lambda d: not isinstance(d, Function), decs))
    func_decs = list(filter(lambda d: isinstance(d, Function), decs))
    non_func_declarations, _ = gen_code(non_func_decs, info, context=DEF)
    non_func_declarations += ('\n/* The globaly shared state is in this structure */'
            + shared_state.get_c_code() + ';\n')
    func_declarations, _ = gen_code(func_decs, info, context=ARG)
    declarations = non_func_declarations + '\n' + func_declarations

    parser_code, _ = gen_code(info.prog.parser_code, info)
    parser_code = info.prog._load_connection_state() + parser_code
    parser_code = indent(parser_code, 1)

    code = ([]
            + info.prog.headers
            + ['typedef char bool;',
                'typedef unsigned long long int size_t;',
                'typedef unsigned char __u8;',
                'typedef unsigned short __u16;',
                'typedef unsigned int __u32;',
                'typedef unsigned long long int __u64;',
'''#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif

#ifndef memmove
#define memmove(d, s, len) __builtin_memmove(d, s, len)
#endif''',
                ]
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

        args = []
        for a in inst.args:
            if isinstance(a, str):
                args.append(a)
            else:
                # remove the semicolon
                text = a.get_c_code()[:-1]
                args.append(text)
        text_args = ', '.join(args)

        # Change the context
        scope = scope_mapping.get(inst.name)
        if not scope:
            raise Exception(f'could not find the scope for function {inst.name}')
        # TODO: simiplify the scope switch process by using a stack in symbol
        # table and exposing an API
        old_scope = info.sym_tbl.current_scope
        info.sym_tbl.current_scope = scope
        body, _ = gen_code(inst.body, info)
        # Change scope back
        info.sym_tbl.current_scope = old_scope

        body = indent(body)
        text = f'{inst.return_type} {inst.name} ({text_args}) {{\n{body}\n}}\n\n'
        return text
    else:
        return inst.get_c_code()


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
