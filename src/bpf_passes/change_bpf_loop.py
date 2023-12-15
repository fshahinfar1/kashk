import clang.cindex as clang
from code_pass import Pass
from utility import find_elems_of_kind, get_tmp_var_name, indent
from data_structure import *
from instruction import *

from passes.clone import clone_pass
from passes.pass_obj import PassObject


RETURN_FIELD_POISON = '999'
RETURN_FIELD_FLAG_NAME = '__loop_ret_flag'
RETURN_FIELD_VAL_NAME = '__loop_ret_val'

ZERO = Literal('0', clang.CursorKind.INTEGER_LITERAL)
ONE  = Literal('1', clang.CursorKind.INTEGER_LITERAL)
class _ConverLoopFuncInst(Pass):
    """
    This pass transforms the loop logic to a valid form in the function passed
    to the 'bpf_loop' helper.
    """
    def process_current_inst(self, inst, more):
        # NOTE: pass specific attributes are:
        # * names_on_struct
        # * ctx_ref
        #
        # `names_on_struct': it is an attribute of this code pass
        # object.  It has the name of the fields on the loop context data
        # structure.
        if inst.kind == clang.CursorKind.DECL_REF_EXPR:
            if inst.name not in self.names_on_struct:
                return inst
            inst.owner.append(self.ctx_ref)
            inst.kind = clang.CursorKind.MEMBER_REF_EXPR
            self.skip_children()
            return inst
        elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
            if len(inst.owner) == 0:
                # it is kind of unexpected
                return inst
            cur_owner = inst.owner[-1]
            if cur_owner.name not in self.names_on_struct:
                return inst
            cur_owner.owner.append(self.ctx_ref)
            cur_owner.kind = clang.CursorKind.MEMBER_REF_EXPR
            self.skip_children()
            return inst
        elif inst.kind == clang.CursorKind.CONTINUE_STMT:
            ret = Return.build([ZERO,])
            self.skip_children()
            return ret
        elif inst.kind == clang.CursorKind.BREAK_STMT:
            ret = Return.build([ONE,])
            self.skip_children()
            return ret
        elif inst.kind == clang.CursorKind.RETURN_STMT:
            if hasattr(inst, '_this_is_new'):
                # TODO: this is a hack to ignore the return instruction I generated my self.
                return inst
            blk = self.cb_ref.get(BODY)
            # set the return flag
            lhs = self.ctx_ref.get_ref_field(RETURN_FIELD_FLAG_NAME, self.info)
            rhs = ONE
            set_flag = BinOp.build(lhs, '=', rhs)
            blk.append(set_flag)
            # store return value on the map and break
            lhs = self.ctx_ref.get_ref_field(RETURN_FIELD_VAL_NAME, self.info)
            rhs = inst.body.children[0]
            obj = _ConverLoopFuncInst.do(rhs, self.info,
                    names_on_struct=self.names_on_struct, ctx_ref=self.ctx_ref)
            rhs = obj.result
            assign = BinOp.build(lhs, '=', rhs)
            blk.append(assign)
            ret = Return.build([ONE,])
            self.skip_children()
            return ret
        elif inst.kind == clang.CursorKind.CALL_EXPR:
            self.current_function.function_dependancy.add(inst.name)
        return inst


_loop_counter = 0
def _get_loop_name():
    global _loop_counter
    name = f'_new_loop_{_loop_counter}'
    _loop_counter += 1
    return name


def _find_all_references(inst):
    """
    Find the references in the loop structure. These are the references we want
    to put on the context structure passed to the loop-function (arg of
    bpf_loop).
    """
    children = inst.get_children()
    looking = (clang.CursorKind.DECL_REF_EXPR,
            clang.CursorKind.MEMBER_REF_EXPR,)
    refs = []
    for target in looking:
        tmp = find_elems_of_kind(children, target)
        refs.extend(tmp)
    # remove references to the values defined in the body
    decls = find_elems_of_kind(inst.body, clang.CursorKind.VAR_DECL)
    decls = set(d.name for d in decls)
    result = []
    for ref in refs:
        if ref.kind == clang.CursorKind.MEMBER_REF_EXPR and len(ref.owner) == 0:
            # This is shared throught the current class context ?
            continue
        name = ref.name if ref.kind == clang.CursorKind.DECL_REF_EXPR else ref.owner[-1].name
        if name in decls:
            continue
        result.append(ref)
    return result


def _define_type_for_passing_state(inst, loop_name, ret_type):
    """
    Form the data structure we use for storing the loop context.
    """
    all_refs = _find_all_references(inst)
    unique_refs = []
    visited_ref_name = set()
    # debug('All references of the loop:', all_refs)
    for ref in all_refs:
        tmp = ref
        if ref.owner:
            # for members we need to only pass the parent
            tmp = ref.owner[-1]
        if tmp.name in visited_ref_name:
            continue
        visited_ref_name.add(tmp.name)
        unique_refs.append(tmp)
    # debug('Unique refs of the loop:', unique_refs)

    # does the for loop return
    ret_list = find_elems_of_kind(inst.body, clang.CursorKind.RETURN_STMT)
    if len(ret_list) > 0:
        ret_ref = Ref.build(RETURN_FIELD_FLAG_NAME,
                BASE_TYPES[clang.TypeKind.UCHAR])
        unique_refs.append(ret_ref)
        ret_ref = Ref.build(RETURN_FIELD_VAL_NAME, ret_type)
        unique_refs.append(ret_ref)

    type_name = loop_name + '_ctx'
    fields = []
    for ref in unique_refs:
        T = ref.type
        if T.is_array():
            T = MyType.make_pointer(T.element_type)
        f = StateObject.build(ref.name, T)
        fields.append(f)
    record = Record(type_name, fields)
    # debug('Type for the loop:\n', record.get_c_code())
    return record


def _define_loop_func(for_inst, ctx_struct, loop_name, info):
    """
    Declare the function which is passed to the bpf_loop helper.
    """
    func_name = loop_name + '_func'
    func = Function(func_name, None)
    func.return_type = BASE_TYPES[clang.TypeKind.LONG]
    arg1 = StateObject.build('index', BASE_TYPES[clang.TypeKind.UINT])
    VOID_PTR = MyType.make_pointer(BASE_TYPES[clang.TypeKind.VOID])
    arg2 = StateObject.build('arg', VOID_PTR)
    func.args = [arg1, arg2]
    func.may_succeed = True

    body = []
    # Get the pointer to the context
    ctx_ptr_type = MyType.make_pointer(ctx_struct.type)
    decl_ll = VarDecl.build('ll', ctx_ptr_type)
    arg_ref = Ref.build(arg2.name, arg2.type_ref)
    decl_ll.init.add_inst(arg_ref)
    body.append(decl_ll)
    ctx_ref = decl_ll.get_ref()

    cond = []
    # Check if the loop condition does not hold, break
    inst = for_inst.cond.children[0]
    cond = clone_pass(inst, info, PassObject())
    paren = Instruction()
    paren.kind = clang.CursorKind.PAREN_EXPR
    paren.body = [cond,]
    cond = UnaryOp.build('!', paren)
    break_int = Literal('1', clang.CursorKind.INTEGER_LITERAL)
    return_inst = Return.build([break_int,])
    return_inst._this_is_new = 1
    check = ControlFlowInst.build_if_inst(cond)
    check.body.add_inst(return_inst)
    body.append(check)
    # The rest of the body as was in the original for loop
    for inst in for_inst.body.children:
        new_inst = clone_pass(inst, info, PassObject())
        body.append(new_inst)
    # Add the POST opeations
    for inst in for_inst.post.children:
        new_inst = clone_pass(inst, info, PassObject())
        body.append(new_inst)
    # Just return from the function
    return_inst = Return.build([ZERO,])
    return_inst._this_is_new = 1
    body.append(return_inst)
    # Name of the fields on the context data structure
    names_on_struct = set(field.name for field in ctx_struct.fields)
    func.body.children = body
    # Add function to symbol table
    func.is_used_in_bpf_code = True
    func.attributes = 'static'
    info.prog.declarations.insert(0, func)
    func.update_symbol_table(info.sym_tbl)
    # Apply transformation needed for instruction on the body of this function
    obj = _ConverLoopFuncInst.do(func.body, info, func=func,
            names_on_struct=names_on_struct, ctx_ref=ctx_ref)
    func.body = obj.result
    return func


class BPFLoopPass(Pass):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._may_remove = True

    def _process_for_loop(self, inst, more):
        assert inst.kind == clang.CursorKind.FOR_STMT
        # debug('Visiting a for loop:', name)
        blk = self.cb_ref.get(BODY)
        name = _get_loop_name()

        # return type is used in-case the for loop has a return instruction in
        # it body.
        ret_type = BASE_TYPES[clang.TypeKind.INT]
        if self.current_function is not None:
            ret_type = self.current_function.return_type
        struct = _define_type_for_passing_state(inst, name, ret_type)
        # Update symbol table with the new type
        tmp = self.info.sym_tbl.current_scope
        self.info.sym_tbl.current_scope = self.info.sym_tbl.global_scope
        struct.update_symbol_table(self.info.sym_tbl)
        self.info.sym_tbl.current_scope = tmp
        self.info.prog.add_declaration(struct)
        # Define the loop function
        iter_func = _define_loop_func(inst, struct, name, self.info)
        # Move instruction in PRE part of the for loop out
        # for (PRE; COND; POST) {BODY}
        for i in inst.pre.children:
            new_inst = clone_pass(i, self.info, PassObject())
            blk.append(new_inst)
        # Declare context on the stack
        var_decl = VarDecl.build(get_tmp_var_name(), struct.type)
        ctx_ref = var_decl.get_ref()
        initialization = []
        for field in struct.fields:
            if field.name in (RETURN_FIELD_FLAG_NAME, RETURN_FIELD_VAL_NAME):
                line = f'.{field.name} = ({field.type_ref.spelling})0'
            else:
                line = f'.{field.name} = {field.name}'
            initialization.append(line)
        text = ',\n'.join(initialization)
        text = indent(text)
        text = f'{{\n{text}\n}};'
        init_inst = Literal(text, CODE_LITERAL)
        var_decl.init.add_inst(init_inst)
        blk.append(var_decl)
        # Call bpf_loop
        call = Call(None)
        call.name = 'bpf_loop'
        # iters = self.info.prog.max_loop_iteration
        iters = Literal(str(inst.repeat), clang.CursorKind.INTEGER_LITERAL)
        ref_t = MyType.make_simple(None, clang.TypeKind.FUNCTIONPROTO)
        func_ref = Ref.build(iter_func.name, ref_t)
        ctx_pointer = UnaryOp.build('&', ctx_ref)
        call.args = [iters, func_ref, ctx_pointer, ZERO]
        blk.append(call)
        # Mark current function dependant on the loop func
        if self.current_function is not None:
            self.current_function.function_dependancy.add(iter_func.name)
        # Also move values out of struct
        for field in struct.fields:
            # TODO: only values that have actually changed
            # Check if the variable gets out of scope?
            if field.name == RETURN_FIELD_VAL_NAME:
                continue
            if field.name == RETURN_FIELD_FLAG_NAME:
                lhs = ctx_ref.get_ref_field(field.name, self.info)
                # rhs = Literal(RETURN_FIELD_POISON, clang.CursorKind.INTEGER_LITERAL)
                # rhs_cast = Cast.build(rhs, lhs.type)
                # cond = BinOp.build(lhs, '!=', rhs_cast)
                rhs = ZERO
                cond = BinOp.build(lhs, '!=', rhs)
                check = ControlFlowInst.build_if_inst(cond)
                ret_ref = ctx_ref.get_ref_field(RETURN_FIELD_VAL_NAME, self.info)
                ret = Return.build([ret_ref,])
                check.body.add_inst(ret)
                blk.append(check)
            else:
                sym = self.info.sym_tbl.current_scope.symbols.get(field.name)
                assert sym is not None, 'Failed to find symbol for a variable which was used in the Loop!'
                if sym.type.is_array():
                    # Do not need to re assign the array
                    continue
                lhs = Ref.build(field.name, sym.type)
                rhs = ctx_ref.get_ref_field(field.name, self.info)
                assingnment = BinOp.build(lhs, '=', rhs)
                blk.append(assingnment)

    def _should_transform_loop(self, inst):
        # TODO: The BPF helper function bpf_loop has some verification bugs
        # which are very annoying. Although it is nice to use it, due to this
        # issue, I am avoiding it.

        if inst.repeat > 32:
            return True
        return False

    def process_current_inst(self, inst, more):
        info = self.info
        if inst.kind == clang.CursorKind.FOR_STMT:
            if self._should_transform_loop(inst):
                self._process_for_loop(inst, more)
                self.skip_children()
                # Remove the for loop
                return None
            else:
                return inst
        return inst

def change_to_bpf_loop(bpf, info, more):
    obj = BPFLoopPass.do(bpf, info, more)
    res = obj.result
    functions = tuple(Function.directory.values())
    for func in functions:
        if not func.is_used_in_bpf_code:
            continue
        # 'do' would change the scope to the given function
        obj = BPFLoopPass.do(func.body, info, more=None, func=func)
        func.body = obj.result
    return res
