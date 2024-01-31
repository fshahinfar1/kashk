import clang.cindex as clang
from log import debug
from data_structure import Function
from utility import find_elems_of_kind


class Node:
    __slots__ = ('name', 'edge')
    def __init__(self, name):
        self.name = name
        self.edge = set()


def find_function_call_dependencies(func_names):
    """
    @param func_name A set of function names of interest
    @returns a list of function names
    """
    table = {}
    set_of_all_nodes_with_out_any_dep = set()
    for name in func_names:
        node = Node(name)
        table[name] = node
        set_of_all_nodes_with_out_any_dep.add(node)
    for name in func_names:
        node = table[name]
        func = Function.directory[name]
        list_calls = find_elems_of_kind(func.body, clang.CursorKind.CALL_EXPR)
        has_dep = False
        relevant_calls = [x.name for x in list_calls if x.name in func_names]
        for dep_name in relevant_calls:
            has_dep = True
            other = table[dep_name]
            other.edge.add(node)
        # If this function has a dependency, remove it from the list
        if has_dep:
            if node in set_of_all_nodes_with_out_any_dep:
                set_of_all_nodes_with_out_any_dep.remove(node)
        # debug(name, 'depends on', relevant_calls)

    order = []
    queue = list(set_of_all_nodes_with_out_any_dep)
    # debug([x.name for x in queue])
    visited = set()
    while queue:
        n = queue.pop()
        order.append(n)
        tmp = list(n.edge)
        for m in tmp:
            n.edge.remove(m)
            has_no_other_edge = True
            for tmp_node in table.values():
                if m in tmp_node.edge:
                    has_no_other_edge = False
                    break
            if has_no_other_edge:
                queue.append(m)
    for tmp_node in table.values():
        if len(tmp_node.edge) > 0:
            raise Exception('Graph has cycles')
    result = [node.name for node in order]
    return result
