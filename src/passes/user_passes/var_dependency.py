import clang.cindex as clang
from log import error, debug
from sym_table import SymbolAccessMode
from data_structure import CodeBlockRef
from instruction import *

from code_pass import Pass
from passes.pass_obj import PassObject

from bpf_code_gen import gen_code


PARENT_BIN_OP = 560
MODULE_TAG = '[Var Dependency]'


def _should_not_share_variable(inst, sym, info):
    if inst.name == 'conn':
        # TODO: figure out what I need to do in this case
        return True
    if inst.bpf_ignore:
        return True
    if 'asio::' in sym.type.spelling:
        return True
    return False


def _is_local(path, inst, info):
    sym, scope = path.scope.lookup2(inst.name)
    if sym is None:
        return False, sym
    if scope == path.scope:
        return True, sym
    if scope == info.sym_tbl.shared_scope:
        return True, sym
    return False, sym


class VarAnalysis(Pass):
    def __init__(self, info):
        super().__init__(info)
        self.path = None
        self.bin_stack = CodeBlockRef()

    def _handle_reference(self, inst, ctx):
        # TODO: since the scope is built before hand, the definitions that
        # come later are also present in this scope.
        # TODO: or if the variable is define before the failure region but
        # in this scope!

        info = self.info
        path = self.path
        parent_bin_op = self.bin_stack.get(PARENT_BIN_OP)
        is_local, sym = _is_local(path, inst, info)
        if not is_local:
            blk = self.cb_ref.get(BODY)
            orig_sym = path.original_scope.lookup(inst.name)
            if orig_sym is None:
                error(f'Variable {inst.name} was not found in the symbol table! Assuming it is not needed in userspace', inst.kind, tag=MODULE_TAG)
            elif _should_not_share_variable(inst, orig_sym, info):
                debug('not share:', inst.name, 'type:', orig_sym.type.spelling, tag=MODULE_TAG)
                decl = VarDecl(None)
                decl.name = inst.name
                decl.type = orig_sym.type
                blk.append(decl)
                sym = path.scope.insert_entry(inst.name, orig_sym.type, orig_sym.kind, None)
            else:
                sym = path.scope.insert_entry(inst.name, orig_sym.type, orig_sym.kind, None)
                if ctx == LHS and parent_bin_op.op == '=':
                    # writing to this unknow variable --> I do not need to share the result
                    debug(f'not caring about {sym.name}', tag=MODULE_TAG)
                    sym.is_accessed = SymbolAccessMode.FIRST_WRITE
                    decl = VarDecl.build(inst.name, orig_sym.type)
                    blk.append(decl)
                else:
                    sym.is_accessed = SymbolAccessMode.HAS_READ
                    path.var_deps.add(sym)
                    if sym.name == 'num_messages':
                        debug('adding:', sym.name, tag=MODULE_TAG)
                        scp = path.scope
                        while scp is not None:
                            print(scp)
                            scp = scp.parent
        else:
            if ctx == LHS and parent_bin_op and parent_bin_op.op == '=':
                sym.is_accessed = SymbolAccessMode.FIRST_WRITE
            else:
                sym.is_accessed = SymbolAccessMode.HAS_READ

    def process_current_inst(self, inst, more):
        # Process instruction
        lvl, ctx, parent_list = more.unpack()
        info = self.info
        path = self.path
        if inst.kind == clang.CursorKind.VAR_DECL:
            sym = path.original_scope.lookup(inst.name)
            if sym is not None:
                path.scope.insert_entry(inst.name, sym.type, inst.kind, None)
            else:
                assert 0, 'The variable was not found in the origin scope'
                # T = inst.type
                # path.scope.insert_entry(inst.name, T, inst.kind, None)
            # debug('learn about:', sym.name, tag=MODULE_TAG)
        elif inst.kind == clang.CursorKind.DECL_REF_EXPR:
            self._handle_reference(inst, ctx)
        elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
            # TODO: I do not need to copy all the struct, just the fields used.
            # TODO: will it work with multiple level of member referencing?
            owner = inst.owner[-1]
            self._handle_reference(owner, ctx)
        elif inst.kind == clang.CursorKind.BINARY_OPERATOR:
            self.bin_stack.push(PARENT_BIN_OP, inst)
        # do not remove the instruction
        return inst

    def end_current_inst(self, inst, more):
        if inst.kind == clang.CursorKind.BINARY_OPERATOR:
            # Pop the parent binary operator
            self.bin_stack.pop()
        # do not remove the instruction
        return inst


def _remove_unused_args(func_obj, call_inst, scope):
    remove = []
    for i, arg in enumerate(func_obj.args):
        sym = scope.lookup(arg.name)
        # print(arg.name, p.code.children, p.scope, func_obj.name)
        assert sym is not None
        if sym.is_accessed != SymbolAccessMode.HAS_READ:
            # debug(f'The variable {sym.name} is not needed in function argument of {func_obj.name}', tag=MODULE_TAG)
            remove.append(i)
        else:
            # debug(f'The variable {sym.name} is needed at {func_obj.name}', tag=MODULE_TAG)
            pass

    debug('removing unsed args:', remove, func_obj.args, call_inst, tag=MODULE_TAG)
    for already_poped, pos in enumerate(remove):
        # debug('Function Object:', func_obj.name, tag=MODULE_TAG)
        pop_index = pos - already_poped
        func_obj.args.pop(pop_index)
        for tmp_c in call_inst:
            # debug('Call instruction:', tmp_c.name, tag=MODULE_TAG)
            if len(tmp_c.args) <= pop_index:
                error('We are trying to remove more arguments than already exists!')
                continue
            tmp_c.args.pop(pop_index)


def _process_node(node, info):
    # First process all the child nodes
    for child in node.children:
        _process_node(child, info)
        child_p = child.paths
        if child_p.func_obj is not None:
            _remove_unused_args(child_p.func_obj, child_p.call_inst, child_p.scope)

    if node.has_code():
        path = node.paths
        tmp = VarAnalysis.do(path.code, info, path=path)
        # debug('Just processed node with id:', id(node), tag=MODULE_TAG)
        new_block = tmp.result 
        path.code = new_block
        # text, _ = gen_code(path.code, info)
        # debug(text, tag=MODULE_TAG)


def var_dependency_pass(info):
    # print('begin')

    # TODO: note there is a difference between root of the graph and body of
    # event loop! maybe there are multiple failure paths in the event loop.
    # this means that some of the intermediate nodes may not have associated
    # new functions. So, some the nodes are not directly converted to the code!
    root = info.user_prog.graph
    _process_node(root, info)
