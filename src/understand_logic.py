import itertools
from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from utility import get_code, report_on_cursor, visualize_ast, skip_unexposed_stmt, get_token_from_source_code, token_to_str
from data_structure import *
from instruction import *
from sym_table import MemoryRegion
from prune import (should_process_this_cursor, should_ignore_cursor, READ_PACKET, WRITE_PACKET)

from parser.for_loop import parse_for_loop_stmt
from parser.switch_case import parse_switch_case

from dfs import DFSPass

MODULE_TAG = '[Understand Pass]'

class _State:
    """
    Holding state on global variables introduce bugs when running different
    instance of computing recursively. This is my attempt to put the state on
    an object and pass the object along the function calls.
    """
    def __init__(self):
        self.cb_ref = CodeBlockRef()
        self.code_for_bpf = True

    def get_global_for_bpf(self):
        return self.code_for_bpf

    @contextmanager
    def set_global_for_bpf(self, val):
        tmp = self.code_for_bpf
        self.code_for_bpf = val
        try:
            yield None
        finally:
            self.code_for_bpf = tmp


def get_variable_declaration_before_elem(cursor, target_cursor):
    variables = []
    d = DFSPass(cursor)
    for c, _ in d:
        if c == target_cursor:
            # Found the target element
            break

        if c.kind == clang.CursorKind.VAR_DECL:
            v = VarDecl(c)
            variables.append(v)

        d.go_deep()
    return variables


def get_all_read(block):
    """
    Get all the read instructions under the cursor
    """
    result = []
    q = [block]
    # Outside the connection polling loop
    while q:
        c = q.pop()

        if c.kind == clang.CursorKind.CALL_EXPR:
            func_name = c.spelling
            if func_name in COROUTINE_FUNC_NAME:
                # These functions are for coroutine and make things complex
                continue

            if c.spelling in READ_PACKET:
                result.append(c)
                continue

        # Continue deeper
        for child in reversed(list(c.get_children())):
            q.append(child)
    return result


def get_all_send(cursor):
    """
    Get all the send system calls under the cursor
    """
    result = []
    d = DFSPass(cursor)
    # Outside the connection polling loop
    for c, _ in d:
        if c.kind == clang.CursorKind.CALL_EXPR:
            func_name = c.spelling
            if func_name in COROUTINE_FUNC_NAME:
                # These functions are for coroutine and make things complex
                continue

            if c.spelling in WRITE_PACKET:
                result.append(c)
                continue

        d.go_deep()
    return result


def _get_init_field(field_cursor):
    """
    This is a helper for parsing the struct initializer fields
    { .f1 = v1, .f2 = v2, ... };
    """
    tmp = list(field_cursor.get_children())
    if len(tmp) == 0:
        # val = gather_instructions_from(field_cursor, None)[0]
        # val_str = val
        key_str = ''
        val_str = field_cursor.spelling
    elif len(tmp) == 1:
        # val = skip_unexposed_stmt(tmp[0])
        # val = gather_instructions_from(val, None)[0]
        # val_str = val
        key_str = ''
        val_str = skip_unexposed_stmt(tmp[0]).spelling
    elif len(tmp) >= 2:
        key = list(map(skip_unexposed_stmt, tmp[0:-1]))
        # val = gather_instructions_from(skip_unexposed_stmt(tmp[-1]), None)[0]
        # val_str = val
        key_str = '.'.join(k.spelling for k in key)
        val_str = skip_unexposed_stmt(tmp[-1]).spelling
    else:
        debug(tmp)
        debug('first child:')
        report_on_cursor(tmp[0])
        report_on_cursor(tmp[1])
        report_on_cursor(tmp[2])
        debug('0000000')
        raise Exception('Not expected!')
    return key_str, val_str


def _create_annotation_inst(value_cursor_children):
    assert len(value_cursor_children) == 2
    msg_field, ann_msg = _get_init_field(value_cursor_children[0])
    # msg_field = msg_field.name
    # ann_msg = ann_msg.text
    kind_field, ann_kind = _get_init_field(value_cursor_children[1])
    # kind_field = kind_field.name
    # ann_kind = ann_kind.name
    # debug(msg_field, ann_msg)
    # debug(kind_field, ann_kind)

    assert msg_field == Annotation.MESSAGE_FIELD_NAME
    assert kind_field == Annotation.KIND_FIELD_NAME
    return Annotation(ann_msg, ann_kind)


def _make_for_loop(cursor, info):
    init, cond, post, body = parse_for_loop_stmt(cursor)
    inst = ForLoop()
    # inst.cursor = c
    inst.cursor = None # TODO: do I need the reference?
    if init:
        inst.pre.extend_inst(gather_instructions_from(init,  info, context=ARG))
    if cond:
        inst.cond.extend_inst(gather_instructions_from(cond, info, context=ARG))
    if post:
        inst.post.extend_inst(gather_instructions_from(post, info, context=ARG))
    if body:
        inst.body.extend_inst(gather_instructions_from(body, info, context=BODY))
    return inst


def _make_switch_case(cursor, info):
    assert cursor.kind == clang.CursorKind.SWITCH_STMT
    sw_cond_cursor, cases = parse_switch_case(cursor, info)
    inst = ControlFlowInst()
    inst.kind = clang.CursorKind.SWITCH_STMT
    cond = gather_instructions_from(sw_cond_cursor, info, context=ARG)
    inst.cond.extend_inst(cond)
    for case in cases:
        case_inst = CaseSTMT(case.cursor, case.kind)
        if case.cond_cursor is not None:
            case_cond = gather_instructions_from(case.cond_cursor, info, ARG)
            case_inst.case.extend_inst(case_cond)
        for body_cursor in case.body_cursors:
            body_insts = gather_instructions_from(body_cursor, info, BODY)
            case_inst.body.extend_inst(body_insts)
        inst.body.add_inst(case_inst)
    return inst


def __convert_cursor_to_inst(c, info, _state):
    if c.kind == clang.CursorKind.CALL_EXPR:
        return understand_call_expr(c, info)
    elif (c.kind == clang.CursorKind.BINARY_OPERATOR
            or c.kind == clang.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR):

        # tmp = [c, ]
        # while tmp:
        #     x = tmp.pop()
        #     report_on_cursor(x)
        #     for y in x.get_children():
        #         tmp.insert(0, y)

        try:
            inst = BinOp(c)
        except Exception as e:
            error('Issuw with BinOp')
            return Literal('<Failed to create Binary Op>', CODE_LITERAL)
        children = c.get_children()

        lhs_child = next(children)
        lhs_inst = gather_instructions_from(lhs_child, info, context=LHS)[0]
        inst.lhs.add_inst(lhs_inst)

        rhs_child = next(children)
        rhs_inst = gather_instructions_from(rhs_child, info, context=RHS)[0]
        inst.rhs.add_inst(rhs_inst)

        inst.ignore = lhs_inst.ignore or rhs_inst.ignore
        return inst
    elif (c.kind == clang.CursorKind.UNARY_OPERATOR
            or c.kind == clang.CursorKind.CXX_UNARY_EXPR):
        inst = UnaryOp(c)
        children = list(c.get_children())
        # report_on_cursor(c)
        if len(children) != 1:
            # TODO: what is happening (error encounter on a line  with `sizeof(int)')
            return Literal('<unknown unary op>', CODE_LITERAL)
        assert len(children) == 1, f'Expected the unary cursor to have 1 child it has {len(children)}'
        child = gather_instructions_from(children[0], info, context=ARG)
        inst.child.extend_inst(child)
        return inst
    elif c.kind == clang.CursorKind.CONDITIONAL_OPERATOR:
        children = c.get_children()
        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond.extend_inst(gather_instructions_from(next(children), info, context=ARG))
        inst.body.extend_inst(gather_instructions_from(next(children), info, context=ARG))
        inst.other_body.extend_inst(gather_instructions_from(next(children), info, context=ARG))
        return inst
    elif c.kind == clang.CursorKind.PAREN_EXPR:
        children = c.get_children()
        inst = Parenthesis()
        inst.body.extend_inst(gather_instructions_from(next(children), info, context=ARG))
        return inst
    elif (c.kind == clang.CursorKind.CXX_REINTERPRET_CAST_EXPR
            or c.kind == clang.CursorKind.CSTYLE_CAST_EXPR
            or c.kind == clang.CursorKind.CXX_STATIC_CAST_EXPR):
        children = list(c.get_children())
        count_children = len(children)
        # TODO: I do not remember why I am doing this check
        assert count_children < 3
        inst = Cast()
        inst.castee.extend_inst(gather_instructions_from(children[-1], info, context=ARG))
        inst.type = MyType.from_cursor_type(c.type)
        return inst
    elif c.kind == clang.CursorKind.DECL_STMT:
        children = c.get_children()
        res = gather_instructions_from(next(children), info, context=ARG)
        if res:
            return res[0]
        # report_on_cursor(c)
        # debug(res)
        error('I am removing an instruction why?')
        return None
    elif c.kind == clang.CursorKind.VAR_DECL:
        inst = VarDecl(c)
        # Find the variable initialization, if there is any.
        init = []
        if inst.type.is_array():
            # debug('declaring an array and initializing:', tag=MODULE_TAG)
            # debug(inst, tag=MODULE_TAG)
            # report_on_cursor(c)
            children = list(c.get_children())
            # debug('array declaration children:', children, tag=MODULE_TAG)
            # assert len(children) == 1
            # for child in children:
            #     if child.kind == clang.CursorKind.INTEGER_LITERAL:
            #         continue
            #     init = gather_instructions_from(child, info, context=ARG)
            #     break
            if len(children) > 1:
                child = children[1]
                init = gather_instructions_from(child, info, context=ARG)
        elif inst.type.is_func_ptr():
            # TODO: what to do whit available information about function pointer decleration?
            # debug('Function pointer?')
            pass
        else:
            init = []
            children = list(c.get_children())
            # TODO: why there is a TYPE_REF in VAR_DECL children?
            # Get rid of TYPE_REF in the init list!
            while children and children[-1].kind == clang.CursorKind.TYPE_REF:
                children.pop()
            if children:
                init = gather_instructions_from(children[-1], info, context=ARG)

        inst.init.extend_inst(init)

        # Add variable to the scope
        if info.sym_tbl.lookup(c.spelling) is not None:
            error(f'{MODULE_TAG} Shadowing variables are not supported and can cause issues! ({c.spelling})')
        entry = inst.update_symbol_table(info.sym_tbl)
        entry.memory_region = MemoryRegion.STACK
        entry.referencing_memory_region = MemoryRegion.STACK
        return inst
    elif c.kind == clang.CursorKind.MEMBER_REF_EXPR:
        inst = Ref(c)
        return inst
    elif (c.kind == clang.CursorKind.DECL_REF_EXPR
            or c.kind == clang.CursorKind.TYPE_REF):
        inst = Ref(c, clang.CursorKind.DECL_REF_EXPR)
        return inst
    elif c.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
        children = c.get_children()

        T = MyType.from_cursor_type(c.type)
        inst = ArrayAccess(T)
        ref = gather_instructions_from(next(children), info, context=ARG)
        assert len(ref) == 1
        ref = ref[0]
        inst.array_ref = ref
        inst.index.extend_inst(gather_instructions_from(next(children), info, context=ARG))
        return inst
    elif c.kind in (clang.CursorKind.CXX_BOOL_LITERAL_EXPR,
            clang.CursorKind.INTEGER_LITERAL,
            clang.CursorKind.FLOATING_LITERAL,
            clang.CursorKind.STRING_LITERAL,
            clang.CursorKind.CHARACTER_LITERAL,):
        try:
            token_text = next(c.get_tokens()).spelling
        except StopIteration:
            # Weirdly there are no token!
            # TODO: Let's try a hack, then I might spend sometime figuring out
            # what is happnening here.
            token_text = get_token_from_source_code(c)
        inst = Literal(token_text, c.kind)
        return inst
    elif c.kind == clang.CursorKind.CONTINUE_STMT:
        inst = Instruction()
        inst.kind = c.kind
        return inst
    elif c.kind == clang.CursorKind.LABEL_STMT:
        inst = Instruction()
        inst.kind = c.kind
        inst.body = c.spelling
    elif c.kind == clang.CursorKind.GOTO_STMT:
        label = next(c.get_children())
        inst = Instruction()
        inst.kind = c.kind
        inst.body = label.spelling
        return inst
    elif c.kind == clang.CursorKind.IF_STMT:
        children = list(c.get_children())
        cond = gather_instructions_from(children[0], info, context=ARG)
        body = []
        other_body = []
        if len(children) > 1:
            body = gather_instructions_from(children[1], info, context=BODY)
        if len(children) > 2:
            other_body = gather_instructions_from(children[2], info, context=BODY)

        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond.extend_inst(cond)
        inst.body.extend_inst(body)
        inst.other_body.extend_inst(other_body)
        return inst
    elif c.kind == clang.CursorKind.DO_STMT:
        children = list(c.get_children())
        body = children[0]
        cond = children[-1]
        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond.extend_inst(gather_instructions_from(cond, info, context=ARG))
        inst.body.extend_inst(gather_instructions_under(body, info, BODY))
        return inst
    elif c.kind == clang.CursorKind.WHILE_STMT:
        children = c.get_children()
        cond = next(children)
        body = next(children)
        inst = ControlFlowInst()
        inst.kind = c.kind
        inst.cond.extend_inst(gather_instructions_from(cond, info, context=ARG))
        inst.body.extend_inst(gather_instructions_under(body, info, context=BODY))
        return inst
    elif c.kind == clang.CursorKind.FOR_STMT:
        # TODO: it will not work when parts of for-loop instruction is omitted. I should fix it.
        # For loop syntax: for(init, cond, post) body
        # each part of this for loop construct can be omitied, but libclang is
        # not telling me which part is missing, here is a hack.
        inst = _make_for_loop(c, info)
        return inst
    elif c.kind == clang.CursorKind.SWITCH_STMT:
        inst = _make_switch_case(c, info)
        return inst
    elif c.kind == clang.CursorKind.CASE_STMT:
        report_on_cursor(c)
        assert False, 'This path is discontinued. The switch statement should generate everything'
        # children = list(c.get_children())
        # inst = CaseSTMT(c)
        # inst.case.extend_inst(gather_instructions_from(children[0], info, context=ARG))
        # inst.body.extend_inst(gather_instructions_from(children[1], info, context=BODY))
        # return inst
    elif c.kind == clang.CursorKind.DEFAULT_STMT:
        assert False, 'This path is discontinued. The switch statement should generate everything'
        # body = next(c.get_children())
        # inst = CaseSTMT(c)
        # inst.body.extend_inst(gather_instructions_from(body, info, context=BODY))
        return inst
    elif c.kind == clang.CursorKind.BREAK_STMT:
        inst = Instruction()
        inst.kind = c.kind
        return inst
    elif c.kind == clang.CursorKind.RETURN_STMT:
        # TODO: Return statement is not updated with Block class
        children = list(c.get_children())
        count_children =  len(children)
        inst = Return()
        if count_children == 0:
            pass
        elif count_children == 1:
            children = gather_instructions_from(children[0], info, context=ARG)
            inst.body.extend_inst(children)
        else:
            raise Exception('Unexpected situation when encountering RETURN_STMT')
        return inst
    elif c.kind == clang.CursorKind.CXX_THROW_EXPR:
        inst = Instruction()
        inst.kind = c.kind
        return inst
    elif c.kind == clang.CursorKind.UNEXPOSED_STMT:
        # Some hacks
        text = get_code(c)
        if text.startswith('co_return'):
            inst = Return()
            return inst
        else:
            error('TODO:')
            report_on_cursor(c)
        return None
    elif c.kind == clang.CursorKind.UNEXPOSED_EXPR:
        children = list(c.get_children())
        if len(children) == 1:
            child = children[0]
            return  __convert_cursor_to_inst(child, info, _state)
        else:
            error('TODO:')
            report_on_cursor(c)
    elif c.kind == clang.CursorKind.NULL_STMT:
        return None
    elif c.kind == clang.CursorKind.COMPOUND_LITERAL_EXPR:
        children = list(c.get_children())
        assert len(children) == 2
        type_cursor  = children[0]
        value_cursor = children[1]
        assert type_cursor.kind == clang.CursorKind.TYPE_REF
        assert value_cursor.kind == clang.CursorKind.INIT_LIST_EXPR
        value_cursor_children = list(value_cursor.get_children())
        while len(value_cursor_children) == 1:
            value_cursor_children = list(value_cursor_children[0].get_children())
        if type_cursor.type.spelling == Annotation.ANNOTATION_TYPE_NAME:
            return _create_annotation_inst(value_cursor_children)
        else:
            error('TODO:')
            report_on_cursor(c)
            return None
    elif c.kind == clang.CursorKind.INIT_LIST_EXPR:
        # It will be a list of tuples. The first t.0 is field name t.1 is its value.
        # The t.0 may be None.
        # report_on_cursor(c)
        children = [_get_init_field(child) for child in c.get_children()]
        inst = Instruction()
        inst.kind = c.kind
        inst.body = children
        # debug(MODULE_TAG, 'INIT_LIST:', inst.list)
        return inst
    elif c.kind == clang.CursorKind.ENUM_DECL:
        enum = Enum.from_cursor(c)
        enum.update_symbol_table(info.sym_tbl.current_scope)
        error('A local declaration of enum was removed from the source code! Need to fix this issue.')
        return None
    else:
        error('TODO:')
        report_on_cursor(c)
        return None


def gather_instructions_from(cursor, info, context=BODY, _state=None):
    """
    Convert the cursor to a instruction
    """
    if _state is None:
        _state = _State()
    ops = []
    _state.cb_ref.push(context, ops)
    d = DFSPass(cursor)
    for c, lvl in d:
        # debug('  ' * lvl, c.kind, c.spelling)
        if should_ignore_cursor(c):
            txt = ''.join(map(lambda x: x.spelling, c.get_tokens()))
            inst = Literal(f'/*<placeholder {txt}>*/', CODE_LITERAL)
            ops.append(inst)
            continue

        if not should_process_this_cursor(c):
            with _state.set_global_for_bpf(False):
                inst = __convert_cursor_to_inst(c, info, _state)
                if inst:
                    inst.ignore = True
                    ops.append(inst)
            continue

        if (c.kind == clang.CursorKind.COMPOUND_STMT
                or c.kind == clang.CursorKind.UNEXPOSED_EXPR):
            d.go_deep()
            continue
        elif c.kind == clang.CursorKind.CXX_TRY_STMT:
            # We do not have `try' statement in C or BPF.
            # The idea is to do what is in the try part and hope for the best!
            # TODO: Maybe do not offload try-except parts. Considering them as
            # stopping condition.

            children = list(c.get_children())
            assert len(children) > 0
            d.enque(children[0], lvl+1)
            continue

        inst = __convert_cursor_to_inst(c, info, _state)


        # TODO: handling the IO frameworks needs a bit of thought
        if inst and inst.kind == clang.CursorKind.CALL_EXPR and inst.name in (READ_PACKET + WRITE_PACKET):
            inst.ignore = True

        if inst:
            ops.append(inst)
    _state.cb_ref.pop()
    return ops


def gather_instructions_under(cursor, info, context, _state=None):
    """
    Get the list of instruction in side a block of code.
    (Expecting the cursor to be a block of code)
    """
    # Gather instructions in this list
    ops = []
    for c in cursor.get_children():
        insts = gather_instructions_from(c, info, context, _state)
        ops.extend(insts)

    return ops


from understand_logic_handler import *
