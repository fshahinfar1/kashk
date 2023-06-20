def number_fallback_graph_pass(info):
    root = info.user_prog.graph
    leafs = []

    q = [root]
    while q:
        node = q.pop()
        if node.is_leaf():
            leafs.append(node)
        q.extend(node.children)

    
    for i, leaf in enumerate(leafs):
        leaf.set_id(i)
