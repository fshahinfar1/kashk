import clang.cindex as clang


def handle_var(inst, info, more):
    lvl = more[0]
    print('  ' * lvl + f'{inst.type} {inst.name};')


def handle_call(inst, info, more):
    lvl = more[0]
    func_name = '__this_function_name_is_not_defined__'
    args = list(inst.args) # a copy of the objects list of argument
    if inst.is_method:
        # find the object having this method
        owners = list(reversed(inst.owner))
        if owners[0] == 'conn':
            # TODO: this is hack fix this
            owners = owners[1:]

        func_name = []
        obj = info.scope
        for x in owners:
            obj = obj.get(x)
            func_name.append(obj.type)
            if not obj:
                raise Exception(f'Object not found: {obj}')
        func_name.append(inst.name)
        func_name = '_'.join(func_name)
        args.append(obj)
    else:
        func_name = inst.name
    print(func_name, '(', args, ');')


def gen_code(list_instructions, info):
    jump_table = {
            clang.CursorKind.CALL_EXPR: handle_call,
            clang.CursorKind.VAR_DECL: handle_var,
            
            }
    count = len(list_instructions)
    print('\n\n')
    q = reversed(list_instructions)
    q = list(zip(q, [0] * count))
    while q:
        inst, lvl = q.pop()
        handler = jump_table.get(inst.kind, lambda x,y,z: None)
        handler(inst, info, [lvl])
