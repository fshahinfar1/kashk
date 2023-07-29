def number_fallback_graph_pass(info):
    root = info.user_prog.graph
    leafs = []

    q = [root]
    while q:
        node = q.pop()
        if node.is_leaf():
            leafs.append(node)
        q.extend(node.children)

    
    for i, leaf in enumerate(leafs, start=1):
        # leaf.set_id(i)
        # if leaf.to_user_inst is not None:
        #     leaf.to_user_inst.path_id = i

        assert leaf.to_user_inst is not None
        path_id = leaf.to_user_inst.path_id
        leaf.set_id(path_id)
