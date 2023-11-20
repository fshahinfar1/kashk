import clang.cindex as clang
from code_pass import Pass
from utility import find_elems_of_kind, get_tmp_var_name, indent
from data_structure import *
from instruction import *

from passes.clone import clone_pass
from passes.pass_obj import PassObject


_loop_counter = 0
def _get_loop_name():
    global _loop_counter
    name = f'_new_loop_{_loop_counter}'
    _loop_counter += 1
    return name


def _find_all_references(inst):
    children = inst.get_children()
    looking = (clang.CursorKind.DECL_REF_EXPR,
            clang.CursorKind.MEMBER_REF_EXPR,)
    refs = []
    for target in looking:
        tmp = find_elems_of_kind(children, target)
        refs.extend(tmp)
    return refs


def _define_type_for_passing_state(all_refs, loop_name):
    unique_refs = []
    visited_ref_name = set()
    debug('All references of the loop:', all_refs)
    for ref in all_refs:
        tmp = ref
        if ref.owner:
            # for members we need to only pass the parent
            tmp = ref.owner[-1]
        if tmp.name in visited_ref_name:
            continue
        visited_ref_name.add(tmp.name)
        unique_refs.append(tmp)
    debug('Unique refs of the loop:', unique_refs)

    type_name = loop_name + '_ctx'
    fields = []
    for ref in unique_refs:
        f = StateObject.build(ref.name, ref.type)
        fields.append(f)
    record = Record(type_name, fields)
    debug('Type for the loop:\n', record.get_c_code())
    return record


def _define_loop_func(for_inst, ctx_struct, loop_name, info):
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

    func.body.children = body

    return func


class BPFLoopPass(Pass):
    def _process_for_loop(self, inst, more):
        blk = self.cb_ref.get(BODY)
        name = _get_loop_name()
        debug('Visiting a for loop:', name)
        refs = _find_all_references(inst)

        struct = _define_type_for_passing_state(refs, name)
        tmp = self.info.sym_tbl.current_scope
        self.info.sym_tbl.current_scope = self.info.sym_tbl.global_scope
        struct.update_symbol_table(self.info.sym_tbl)
        self.info.sym_tbl.current_scope = tmp
        self.info.prog.add_declaration(struct)

        iter_func = _define_loop_func(inst, struct, name, self.info)
        iter_func.is_used_in_bpf_code = True
        self.info.prog.declarations.insert(0, iter_func)
        iter_func.update_symbol_table(self.info.sym_tbl)

        # Move instruction in PRE part of the for loop out
        # for (PRE; COND; POST) {BODY}
        for inst in inst.pre.children:
            new_inst = clone_pass(inst, self.info, PassObject())
            blk.append(inst)

        # Declare context on the stack
        var_decl = VarDecl.build(get_tmp_var_name(), struct.type)
        ctx_ref = var_decl.get_ref()
        initialization = []
        for field in struct.fields:
            initialization.append(f'.{field.name} = {field.name}')
        text = ',\n'.join(initialization)
        text = indent(text)
        text = f'{{\n{text}\n}};'
        init_inst = Literal(text, CODE_LITERAL)
        var_decl.init.add_inst(init_inst)
        blk.append(var_decl)

        # Call bpf_loop
        call = Call(None)
        call.name = 'bpf_loop'
        iters = self.info.prog.max_loop_iteration
        ref_t = MyType.make_simple(None, clang.TypeKind.FUNCTIONPROTO)
        func_ref = Ref.build(iter_func.name, ref_t)
        call.args = [iters, func_ref]
        blk.append(call)

        # Also move values out of struct
        for field in struct.fields:
            # TODO: only values that have actually changed
            # Check if the variable gets out of scope?
            lhs = Ref.build(field.name, field.type_ref)
            rhs = ctx_ref.get_ref_field(field.name, self.info)
            assingnment = BinOp.build(lhs, '=', rhs)
            blk.append(assingnment)

    def process_current_inst(self, inst, more):
        info = self.info
        if inst.kind == clang.CursorKind.FOR_STMT:
            self._process_for_loop(inst, more)
            self.skip_children()
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
