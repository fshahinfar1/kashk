from passes.pass_obj import PassObject


def _do_pass(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
    new_children = []

    # Continue deeper
    for child, tag in inst.get_children_context_marked():
        if isinstance(child, list):
            new_child = []
            for i in child:
                obj = PassObject.pack(lvl+1, tag, new_child)
                new_inst = _do_pass(i, info, obj)
                new_child.append(new_inst)
        else:
            obj = PassObject.pack(lvl+1, tag, parent_list)
            new_child = _do_pass(child, info, obj)
        new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def clone_pass(inst, info, more):
    return _do_pass(inst, info, more)
