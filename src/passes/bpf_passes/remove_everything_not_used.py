import clang.cindex as clang
from utility import get_actual_type
from dfs import DFSPass
from log import debug, error, report
from data_structure import Record
from instruction import Ref


MODULE_TAG = '[Remove]'


def _do_pass(bpf, all_declarations, shared_vars, info):
    d = DFSPass(bpf)
    for inst, _ in d:
        keys = None
        if inst.kind == clang.CursorKind.CALL_EXPR:
            # step into the function
            func = inst.get_function_def()
            if func and not func.is_empty():
                _do_pass(func.body, all_declarations, shared_vars, info)
            keys = [inst.name,] # Keep this function
            if func is not None:
                for arg in func.args:
                    type_name = get_actual_type(arg.type).spelling
                    keys.append(type_name) # Keep this type
        elif inst.kind == clang.CursorKind.VAR_DECL:
            type_name = get_actual_type(inst.type).spelling
            keys = [type_name,] # Keep this type
            if inst.type.is_record():
                # This type is compound, also keep every type in the fields
                type_name2 = type_name[len('struct '):]
                decl = Record.directory.get(type_name2)
                if decl:
                    for field in decl.fields:
                        if field.type_ref.is_record():
                            t_name = get_actual_type(field.type_ref).spelling
                            keys.append(t_name)
                else:
                    # debug(MODULE_TAG, 'Did not found decleration for', type_name2)
                    pass
        elif isinstance(inst, Ref):
            # Found a used variable, check if it is in our list.
            var_name = inst.name
            if var_name in shared_vars:
                shared_vars.remove(var_name)
                type_name = get_actual_type(inst.type).spelling
                keys = [type_name,]

        # Remove the types that was found useful
        if keys is not None:
            for k in keys:
                if k in all_declarations:
                    all_declarations.remove(k)
            continue
        d.go_deep()
    return bpf


def remove_everything_not_used(bpf, info, more):
    shared_scope_vars = [v.name
            for v in info.sym_tbl.shared_scope.symbols.values()]
    all_declarations = [decl.get_name()
            for decl in info.prog.declarations
            if (hasattr(decl, 'get_name') and
                not decl.get_name().startswith('enum'))]
    _do_pass(bpf, all_declarations, shared_scope_vars, info)
    # The names which remain in the lists (i.e., `all_declarations' and
    # `shared_scope_vars') after the pass must be removed

    # debug('These shared scope variables should be removed:', shared_scope_vars)
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
