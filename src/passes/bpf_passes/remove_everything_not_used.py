import clang.cindex as clang
from utility import get_actual_type, find_elems_of_kind, PRIMITIVE_TYPES
from data_structure import Function
from dfs import DFSPass
from log import debug, error, report
from instruction import Ref
from my_type import MyType
from passes.code_pass import Pass
from passes.find_unused_vars import find_unused_vars
from var_names import SHARED_REF_NAME


MODULE_TAG = '[Remove]'


class RemoveDecl(Pass):
    def __init__(self, info):
        super().__init__(info)
        self.target = None
        self._may_remove = True

    def process_current_inst(self, inst, more):
        if self.target is not None and inst.kind == clang.CursorKind.VAR_DECL:
            if inst.name in self.target:
                return None
        return inst


def __keep_this_type(T):
    if T.is_mem_ref() or T.spelling in PRIMITIVE_TYPES:
        return []

    type_names = []
    type_name = get_actual_type(T).spelling
    type_names.append(type_name)
    if T.is_record():
        # This type is compound. Also keep every type in the fields
        decl = T.get_decl()
        if not decl:
            return type_names
        for field in decl.fields:
            tmp_type = get_actual_type(field.type)
            tmp = __keep_this_type(tmp_type)
            type_names.extend(tmp)
    return type_names


def _do_pass(bpf, all_declarations, shared_vars, info):
    """
    Go through a block of code and body of functions it calls. Look for types
    and global variables that are used. Mark the rest to be removed.
    """
    d = DFSPass(bpf)
    for inst, _ in d:
        keys = []
        if inst.kind == clang.CursorKind.CALL_EXPR:
            # step into the function
            func = inst.get_function_def()
            if func and not func.is_empty():
                _do_pass(func.body, all_declarations, shared_vars, info)
            keys.append(inst.name) # Keep this function
            # if func is not None:
            #     for arg in func.args:
            #         type_name = get_actual_type(arg.type).spelling
            #         keys.append(type_name) # Keep this type
        elif inst.kind == clang.CursorKind.VAR_DECL:
            tmp_type = get_actual_type(inst.type)
            tmp_k = __keep_this_type(tmp_type)
            keys.extend(tmp_k)
        elif inst.kind == clang.CursorKind.DECL_REF_EXPR:
            # Found a used variable, check if it is in our list.
            var_name = inst.name
            if var_name in shared_vars:
                shared_vars.remove(var_name)
                type_name = get_actual_type(inst.type).spelling
                keys.append(type_name)
            # NOTE: this is a hack that I need to think about
            if var_name.endswith('_map'):
                if var_name in all_declarations:
                    keys.append(var_name)
            # Check if we need the type
            tmp_type = get_actual_type(inst.type)
            tmp_k = __keep_this_type(tmp_type)
            keys.extend(tmp_k)
        elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
            assert len(inst.owner) == 1, f'unexpected length: {len(inst.owner)}'
            owner = inst.owner[-1]
            if owner.kind not in (clang.CursorKind.DECL_REF_EXPR,
                    clang.CursorKind.MEMBER_REF_EXPR):
                # Seems there is nothing to do
                pass
            elif owner.name == SHARED_REF_NAME:
                # TODO: I do not remember this
                var_name = inst.name
                if var_name in shared_vars:
                    shared_vars.remove(var_name)
                    type_name = get_actual_type(inst.type).spelling
                    keys.append(type_name)

            # Check if we need the type
            tmp_type = get_actual_type(inst.type)
            tmp_k = __keep_this_type(tmp_type)
            keys.extend(tmp_k)

            _do_pass(owner, all_declarations, shared_vars, info)

        # Remove the types that was found useful from the list
        for k in keys:
            if k in all_declarations:
                all_declarations.remove(k)

        d.go_deep()
    return bpf


def remove_unused_local_variables(bpf, info, more):
    var_decls = find_elems_of_kind(bpf, clang.CursorKind.VAR_DECL)
    var_names = set(v.name for v in var_decls)
    to_be_removed = find_unused_vars(bpf, info, var_names)
    debug('remove local vars:', to_be_removed, tag=MODULE_TAG)
    res = RemoveDecl.do(bpf, info, more, target=to_be_removed)
    return res.result


def global_remove_unused_local_variables(bpf, info, more):
    bpf = remove_unused_local_variables(bpf, info, None)
    for func in Function.directory.values():
        if func.is_empty() or not func.is_used_in_bpf_code:
            continue
        tmp = remove_unused_local_variables(func.body, info, None)
        func.body = tmp
    return bpf


def remove_everything_not_used(bpf, info, more):
    bpf = global_remove_unused_local_variables(bpf, info, more)
    shared_scope_vars = [v.name
            for v in info.sym_tbl.shared_scope.symbols.values()]
    all_declarations = [decl.get_name()
            for decl in info.prog.declarations
            if (hasattr(decl, 'get_name') and
                not decl.get_name().startswith('enum'))]
    _do_pass(bpf, all_declarations, shared_scope_vars, info)
    # The names which remain in the lists (i.e., `all_declarations' and
    # `shared_scope_vars') after the pass must be removed

    debug('These shared scope variables should be removed:', shared_scope_vars, tag=MODULE_TAG)
    for var_name in shared_scope_vars:
        # NOTE: assuming variable name and scope keys are the same.
        info.sym_tbl.shared_scope.delete(var_name)

    new_list = []
    debug(MODULE_TAG, 'List of declarations to remove:', all_declarations)
    for decl in info.prog.declarations:
        if not hasattr(decl, 'get_name'):
            new_list.append(decl)
            continue

        for name in all_declarations:
            if decl.get_name() == name:
                # remove declaration
                break
        else:
            new_list.append(decl)
    info.prog.declarations = new_list
    return bpf
