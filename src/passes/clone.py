from passes.pass_obj import PassObject


def _do_pass(inst):
    new_children = []

    # Continue deeper
    for child, tag in inst.get_children_context_marked():
        if isinstance(child, list):
            new_child = []
            for i in child:
                new_inst = _do_pass(i)
                new_child.append(new_inst)
        else:
            new_child = _do_pass(child)
        new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


def clone_pass(inst, info=None, more=None):
    return _do_pass(inst)
