import clang.cindex as clang
from log import debug, error
from data_structure import *
from instruction import *
from utility import (indent, INDENT, report_on_cursor, get_actual_type)
from prune import READ_PACKET, WRITE_PACKET
from template import (license_text, shared_map_decl)
from helpers.function_call_dependency import find_function_call_dependencies2


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
    elif inst.type.is_pointer() and inst.type.get_pointee().is_array():
        dimensions = []
        t = inst.type.get_pointee()
        while t.is_array():
            dimensions.append(t.element_count)
            t = t.element_type
        d = ''.join([f'[{str(x)}]' for x in dimensions])
        text = f'{t.spelling} (* {inst.name}){d}'
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


def handle_init_list_expr(inst, info, more):
    tmp = []
    for field_name, field_val in inst.body:
        # debug(field_name, field_val, tag=MODULE_TAG)
        if field_name:
            tmp.append(f'.{field_name} = {field_val}')
        else:
            tmp.append(str(field_val))
    tmp = ','.join(tmp)
    tmp = '{' + tmp + '}'
    return tmp


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
    if inst.body.has_children():
        body, _ = gen_code(inst.body, info, context=ARG)
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
        clang.CursorKind.INIT_LIST_EXPR: handle_init_list_expr,
        # Control FLow
        clang.CursorKind.LABEL_STMT: lambda x,y,z: indent(f'{x.body.text}:', z[0]),
        clang.CursorKind.GOTO_STMT: lambda x,y,z: indent(f'goto {x.body.text}', z[0]),
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
        #
        BLOCK_OF_CODE: lambda x,y,z: indent(f'// {str(x.children)}\n', z[0]),
        }


def gen_code(list_instructions, info, context=BODY):
    if isinstance(list_instructions, Block):
        list_instructions = list_instructions.get_children()
    elif isinstance(list_instructions, Instruction):
        # During debugging, I have many times passed a single instruction
        # instead of a list to this function. Just saving my self some slack.
        list_instructions = [list_instructions, ]
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
            text += '\n\n'
        else:
            # Some special rules
            if inst.kind == clang.CursorKind.CALL_EXPR and inst.name == 'operator<<':
                text = f'// removing a call to "<<" operator'
                modified = CHANGE_BUFFER_DEF
            elif inst.kind == ANNOTATION_INST:
                if not inst.is_block_annotation() or not inst.has_children():
                    text = f'/* Annotation: {inst.msg}*/\n'
                else:
                    text, _ = gen_code(inst.block, info, BODY)
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
                if inst.kind != CODE_LITERAL:
                    text += ';\n'
                else:
                    text += '\n'
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
                error('Unexpected: Function argument is a string!', tag=MODULE_TAG)
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
        before = f'{inst.attributes}'
        if before:
            before += '\n'
        text = f'{before}{inst.return_type.spelling} {inst.name} ({text_args}) {{\n{body}\n}}'
        return text
    else:
        text = inst.get_c_code()
        return text


def __generate_shared_state(info):
    fields = []
    for x in info.sym_tbl.shared_scope.symbols.values():
        o = StateObject(None)
        o.name = x.name
        o.type_ref = x.type
        fields.append(o)
    # If there are any global state, declare the shared_map
    if fields:
        shared_state = Record('shared_state', fields)
        shared_state.update_symbol_table(info.sym_tbl)
        shared_state_struct_decl = (
                '/* The globaly shared state is in this structure */\n'
                + shared_state.get_c_code()
                + '\n'
                + shared_map_decl().get_c_code()
                + '\n'
                )
    else:
        shared_state_struct_decl = ''
    return shared_state_struct_decl


def __sort_declarations(decls, ignore_self_dep=True):
    orig_len = len(decls)
    res = [d for d in decls if not isinstance(d, Record)]
    record = tuple(filter(lambda d: isinstance(d, Record), decls))
    relevant_record_names = set(r.name for r in record)
    # debug('Relevant records:', relevant_record_names, tag=MODULE_TAG)
    R = {}
    deps = {}
    for r in record:
        name = r.name
        assert name not in R, f'multiple declaration of same thing {r}'
        assert name not in deps, f'multiple declaration of same thing {r}'
        R[name] = r
        dep_list = set()
        for f in r.fields:
            T = get_actual_type(f.type)
            if not T.is_record():
                continue
            type_name = T.spelling[len('struct '):]
            if type_name not in relevant_record_names:
                continue
            if ignore_self_dep and type_name == name:
                continue
            dep_list.add(type_name)
        # debug(name, ':', dep_list, tag=MODULE_TAG)
        deps[name] = dep_list

    while len(deps.keys()) > 0:
        # Get records with out any dependency
        no_dep = tuple(name for name, v in deps.items() if len(v) == 0)
        if len(no_dep) == 0:
            # debug(list(deps.items()))
            error('Circular dependancy found between records! Failed to sort them based on dependencies.')
            for name in deps:
                r = R[name]
                res.append(r)
            break
        for record_name in no_dep:
            r = R[record_name]
            res.append(r)
            del deps[record_name]
            for k, v in deps.items():
                if record_name in v:
                    v.remove(record_name)
    assert len(res) == orig_len
    return res


def generate_bpf_prog(info):
    shared_state_struct_decl = __generate_shared_state(info)

    decs = list(info.prog.declarations)
    non_func_decs = list(filter(lambda d: not isinstance(d, Function), decs))
    func_decs = list(filter(lambda d: isinstance(d, Function), decs))
    non_func_decs = __sort_declarations(non_func_decs)
    non_func_declarations, _ = gen_code(non_func_decs, info, context=DEF)
    non_func_declarations += shared_state_struct_decl

    func_decs = find_function_call_dependencies2(func_decs)
    func_declarations, _ = gen_code(func_decs, info, context=ARG)
    declarations = (non_func_declarations + func_declarations)

    bpf_code = info.prog.gen_code(info)
    code = ([]
            + info.prog.headers
            + ['']
            + [declarations]
            + ['']
            + [bpf_code]
            + ['']
            + [license_text(info.prog.license),]
            )
    return '\n'.join(code)
