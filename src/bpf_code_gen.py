import clang.cindex as clang

from data_structure import *
from instruction import *
from utility import (indent, INDENT, report_on_cursor)
from prune import READ_PACKET, WRITE_PACKET

from template import (memcpy_internal_defs, license_text, shared_map_decl)

MODULE_TAG = '[BPF Code Gen]'


def handle_var(inst, info, more):
    lvl = more[0]
    if inst.is_array:
        el_type = inst.type.element_type.spelling
        el_count = inst.type.element_count

        # The following lines of code is for handling the multi-dimensional arrays.
        sub_var = VarDecl(None)
        sub_var.type = inst.type.element_type
        sub_var.name = inst.name
        tmp = handle_var(sub_var, info, more) # recursion
        if sub_var.is_array:
            first_brack = tmp.find('[')
            # insert the array dimension before the current existing ones
            text = f'{tmp[:first_brack]}[{el_count}]{tmp[first_brack:]}'
        else:
            text = f'{tmp}[{el_count}]'
    else:
        text = f'{inst.type.spelling} {inst.name}'
    if inst.init.has_children():
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
    # TODO: in case of ++ operator, it makes a difference if it is before or
    # after the `child'. Currently it can introduce bugs in the generated
    # program because of not considering this.

    if inst.op == 'sizeof':
        text = f'sizeof({child})'
    elif inst.comes_after:
        text = f'{child}{inst.op}'
    else:
        text = f'{inst.op}{child}'
    return text


def handle_ref_expr(inst, info, more):
    lvl = more[0]

    # The case for function pointers is simple
    if inst.is_func_ptr():
        text = inst.name
        text = indent(text, lvl)
        return text

    # Check if the variable is shared globally or per_connection.
    # These variables are placed on a MAP.
    sym, scope = info.sym_tbl.lookup2(inst.name)
    is_global = scope == info.sym_tbl.global_scope
    is_shared = scope == info.sym_tbl.shared_scope
    if is_global and not sym.type.is_enum():
        text = 'sock_ctx->state.' + inst.name
    elif is_shared:
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
        links = []
        # recursivly go through the owner list
        obj = inst.owner[0]
        text, _ = gen_code([obj], info)
        links.append(text)
        if obj.kind == clang.CursorKind.CALL_EXPR:
            func = obj.get_function_def()
            assert func is not None
            type = func.return_type
        else:
            type = obj.type
        link = '->' if type.is_pointer() else '.'
        links.append(link)
        links.append(inst.name)
        text = ''.join(links)
    text = indent(text, lvl)
    return text

def handle_array_sub(inst, info, more):
    lvl = more[0]
    name, _ = gen_code([inst.array_ref,], info, context=ARG)
    index, _ = gen_code(inst.index, info, context=ARG)
    text = f'{name}[{index}]'
    text = indent(text, lvl)
    return text


def handle_cast_expr(inst, info, more):
    lvl = more[0]
    body, _ = gen_code(inst.castee, info, context=ARG)
    if isinstance(inst.type, str):
        ctype = inst.type
    else:
        ctype = inst.type.spelling
    text = f'({ctype})({body})'
    text = indent(text, lvl)
    return text


def handle_literal(inst, info, more):
    lvl = more[0]
    return indent(inst.text, lvl)


def handle_if_stmt(inst, info, more):
    lvl = more[0]

    body, _ = gen_code(inst.body, info, context=BODY)
    body = indent(body, 1)
    cond, _ = gen_code(inst.cond, info, context=ARG)
    text = f'if ({cond}) {{\n' + body + '\n}'
    if inst.other_body.has_children():
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


def handle_while_stmt(inst, info, more):
    lvl = more[0]
    cond, _ = gen_code(inst.cond, info, context=ARG)
    body, _ = gen_code(inst.body, info, context=BODY)
    body = indent(body, 1)
    text = f'while ({cond}) {{\n' + body + '\n}'
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
    if body:
        text = f'return ({body})'
    else:
        text = f'return'
    text = indent(text, lvl)
    return text


def handle_to_userspace(inst, info, more):
    lvl = more[0]
    if inst.is_bpf_main:
        tmp_stmt = f'return {info.prog.get_pass()};'
    elif inst.return_type.spelling == 'void':
        tmp_stmt = 'return;'
    else:
        tmp_stmt = f'return ({inst.return_type.spelling})0;'
    text = ('/* Return from this point to the caller */\n'
            + f'{tmp_stmt}')
    text = indent(text, lvl)
    return text


# Put semi-colon and go to next line after these nodes
NEED_SEMI_COLON = (clang.CursorKind.CALL_EXPR, clang.CursorKind.VAR_DECL,
    clang.CursorKind.BINARY_OPERATOR, clang.CursorKind.CONTINUE_STMT,
    clang.CursorKind.DO_STMT, clang.CursorKind.RETURN_STMT,
    clang.CursorKind.CONTINUE_STMT, clang.CursorKind.BREAK_STMT,
    clang.CursorKind.CXX_THROW_EXPR, clang.CursorKind.UNARY_OPERATOR,
    clang.CursorKind.GOTO_STMT)

# Go to next line after these nodes
GOTO_NEXT_LINE = (clang.CursorKind.IF_STMT, clang.CursorKind.FOR_STMT,
        clang.CursorKind.SWITCH_STMT, clang.CursorKind.CASE_STMT,
        clang.CursorKind.DEFAULT_STMT, CODE_LITERAL, TO_USERSPACE_INST,
        clang.CursorKind.WHILE_STMT, clang.CursorKind.LABEL_STMT,)

NO_MODIFICATION = 0
REPLACE_READ = 1
CHANGE_BUFFER_DEF = 2

# A jump table for generating code based on instruction kind
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
        clang.CursorKind.MACRO_INSTANTIATION: handle_literal,
        CODE_LITERAL: handle_literal,
        # Control FLow
        clang.CursorKind.LABEL_STMT: lambda x,y,z: indent('{x.label}:', z[0]),
        clang.CursorKind.GOTO_STMT: lambda x,y,z: indent('goto {x.label}', z[0]),
        clang.CursorKind.IF_STMT: handle_if_stmt,
        clang.CursorKind.DO_STMT: handle_do_stmt,
        clang.CursorKind.WHILE_STMT: handle_while_stmt,
        clang.CursorKind.FOR_STMT: handle_for_stmt,
        clang.CursorKind.SWITCH_STMT: handle_switch_stmt,
        clang.CursorKind.CASE_STMT: handle_case_stmt,
        clang.CursorKind.DEFAULT_STMT: handle_default_stmt,
        clang.CursorKind.CONDITIONAL_OPERATOR: handle_conditional_op,
        #
        clang.CursorKind.PAREN_EXPR: handle_paren_expr,
        #
        clang.CursorKind.BREAK_STMT: lambda x,y,z: indent('break', z[0]),
        clang.CursorKind.CONTINUE_STMT: lambda x,y,z: indent('continue', z[0]),
        clang.CursorKind.RETURN_STMT: handle_return_stmt,
        clang.CursorKind.CXX_THROW_EXPR: lambda x,y,z: indent('return SK_DROP', z[0]),
        #
        TO_USERSPACE_INST: handle_to_userspace,
        }


def gen_code(list_instructions, info, context=BODY):
    if isinstance(list_instructions, Block):
        list_instructions = list_instructions.get_children()
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
            if isinstance(inst, Record):
                text += ';\n'
        else:
            # Some special rules
            if inst.kind == clang.CursorKind.CALL_EXPR and inst.name == 'operator<<':
                text = f'// removing a call to "<<" operator'
                modified = CHANGE_BUFFER_DEF
            elif inst.kind == ANNOTATION_INST:
                continue
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


def __generate_code_type_definition(inst, info):
    if isinstance(inst, Function):
        if inst.name in (*READ_PACKET, *WRITE_PACKET):
            return ''
        args = []
        for a in inst.args:
            if isinstance(a, str):
                args.append(a)
                error('Unexpected: Function argument is a string!')
            else:
                # remove the semicolon
                text = a.get_c_code()[:-1]
                args.append(text)
        text_args = ', '.join(args)

        # Change the context
        with info.sym_tbl.with_func_scope(inst.name):
            scope = info.sym_tbl.current_scope
            scp_num = scope.number
            # debug('inside:', inst.name, 'scope', f'(scope number: {scp_num})')
            body, _ = gen_code(inst.body, info)
            # debug('out of',inst.name, 'scope')

        body = indent(body)
        text = f'static inline\n{inst.return_type.spelling} {inst.name} ({text_args}) {{\n{body}\n}}\n\n'
        return text
    else:
        text = inst.get_c_code()
        return '\n\n' + text


def __generate_global_shared_state(info):
    fields = []
    for x in info.sym_tbl.shared_scope.symbols.values():
        # debug(MODULE_TAG, x)
        o = StateObject(None)
        o.name = x.name
        o.type_ref = x.type

        fields.append(o)
    # If there are any global state, declare the shared_map
    if fields:
        shared_state = Record('shared_state', fields)
        shared_state_struct_decl = (
                '\n/* The globaly shared state is in this structure */\n'
                + shared_state.get_c_code() + ';\n\n'
                + shared_map_decl() + '\n'
                )
    else:
        shared_state_struct_decl = ''
    return shared_state_struct_decl


def __sort_by_function_depandancy(funcs):
    # TODO: the sorting should consider the graph of dependancy not the number
    # of functions.
    new = sorted(funcs, key=lambda x: len(x.function_dependancy))
    return new


def generate_bpf_prog(info):
    shared_state_struct_decl = __generate_global_shared_state(info)

    decs = list(info.prog.declarations)
    non_func_decs = list(filter(lambda d: not isinstance(d, Function), decs))
    func_decs = list(filter(lambda d: isinstance(d, Function), decs))
    non_func_declarations, _ = gen_code(non_func_decs, info, context=DEF)
    non_func_declarations += shared_state_struct_decl

    func_decs = __sort_by_function_depandancy(func_decs)
    func_declarations, _ = gen_code(func_decs, info, context=ARG)
    declarations = (non_func_declarations + '\n' + func_declarations)

    bpf_code = info.prog.gen_code(info)
    code = ([]
            + info.prog.headers
            + ['typedef char bool;', memcpy_internal_defs()]
            + [declarations]
            + ['']
            + [bpf_code]
            + ['']
            + [license_text(info.prog.license),]
            )
    return '\n'.join(code)
