import clang.cindex as clang
from log import *
from instruction import *
from data_structure import *
from bpf_code_gen import gen_code

class CFGBaseNode:
    Simple = 100
    Branch = 101
    Switch = 102

    node_id = 0
    def __init__(self, kind):
        self._id = CFGBaseNode.node_id
        CFGBaseNode.node_id += 1
        self.kind = kind

class CFGSwitch(CFGBaseNode):
    def __init__(self):
        super().__init__(CFGBranch.Switch)
        self.cond = None
        self.jmps = []

class CFGBranch(CFGBaseNode):
    def __init__(self):
        super().__init__(CFGBaseNode.Branch)
        self.cond = None
        self.if_true = None
        self.if_false = None

class CFGNode(CFGBaseNode):
    def __init__(self):
        super().__init__(CFGNode.Simple)
        self.insts = []
        self.next = None

    def add(self, inst):
        self.insts.append(inst)

    def connect(self, node, join=False):
        assert self.next == None
        if not join and isinstance(node, CFGNode):
            if node.next is None:
                # Merge two nodes
                self.insts.extend(node.insts)
                return self
            elif len(node.insts) == 0:
                # Remove empty sub-root
                self.next = node.next
                return self

        self.next = node
        return node
    
    def is_empty(self):
        return len(self.insts) == 0 and self.next is None


class HTMLWriter:
    def __init__(self):
        self.used_ids = set()

    def _node_to_html(self, node, info):
        if node is None:
            return ''

        if node._id in self.used_ids:
            return ''
        self.used_ids.add(node._id)

        if isinstance(node, CFGNode):
            
            insts = [f'<p class="codetext">"{gen_code([i], info)[0]}"</p>' for i in node.insts]
            text = [
                    f'<div id={node._id} class="node">',
                    f'<p class="nodeid">id: {node._id}</p>',
                    f'<p class="nodeid">to: {node.next._id if node.next is not None else "-"}</p>',
                    ] + insts + ['</div>',]
            text = '\n'.join(text)
            text += '\n' + self._node_to_html(node.next, info)
            return text
        if isinstance(node, CFGBranch):
            cond_text = gen_code(node.cond, info)[0]
            insts = [
                    f'<p class="nodeid">id: {node._id}</p>',
                    f'<p class="nodeid">true: {node.if_true._id if node.if_true else "-"}</p>',
                    f'<p class="nodeid">false: {node.if_false._id if node.if_false else "-"}</p>',
                    f'<p class="codetext">Branch on "{cond_text}"</p>',
                    ]
            text = [f'<div id={node._id} class="node">',] + insts + ['</div>',]
            text = '\n'.join(text)
            text += '\n' + self._node_to_html(node.if_true, info)
            text += '\n' + self._node_to_html(node.if_false, info)
            return text
        if isinstance(node, CFGSwitch):
            cases = []
            other_nodes_text = [] 
            for cond, n in node.jmps:
                cond_text, _ = gen_code(cond, info)
                cases.append(f'<p>on "{cond_text}": {n._id if n._id else "-"}</p>')
                other_nodes_text.append(self._node_to_html(n, info))
            cond_text = gen_code(node.cond, info)[0]
            insts = [ f'<p class="nodeid">id: {node._id}</p>',] + cases + [f'<p class="codetext">Switch on "{cond_text}"</p>', ]
            text = [f'<div id={node._id} class="node">',] + insts + ['</div>',]
            text = '\n'.join(text)
            text += '\n' + '\n'.join(other_nodes_text)
            return text
        raise Exception('Unexpected!')

    def cfg_to_html(self, node, info):
        text = self._node_to_html(node, info)
        res = [
            '<!DOCTYPE html>',
            '<head>',
            '<title>CFG</title>',
            '<style>',
            'body { display: flex; justify-content: flex-start; align-content: flex-start; flex-direction: row;}',
            '.node { border: black 1pt solid; display: inline-block; padding: 2pt}',
            '.node .nodeid { border-bottom: black 1pt dotted; font-size: 12pt;}',
            '.node .codetext { font-size: 8pt;}',
            '</style>',
            '</head>',
            '<body>',
            text,
            '</body>',
            ]
        return '\n'.join(res)


def _leafs(node, visited=None):
    """
    Retrive leaf nodes by traversing the possible paths from the given node.

    The assumption is that leaf nodes are of type CFGNode
    """
    visited = set() if visited is None else visited
    if node is None or node._id in visited:
        return []

    visited.add(node._id)

    if isinstance(node, CFGNode):
        """
        This is implementing the base case of recursion.
        """
        if node.next is None:
            return [node]
        ptr = node
        while isinstance(ptr, CFGNode):
            if ptr.next is not None:
                ptr = ptr.next
            else:
                return [ptr]
        node = ptr
    
    if isinstance(node, CFGSwitch):
        """
        Gather all leaf nodes from all cases. Remove duplicates and return the
        results.
        """
        l = []
        for x in (_leafs(n) for _, n in node.jmps):
            l.extend(x)
        l = list(set(l))
        return l

    
    assert isinstance(node, CFGBranch)
    l = list(set(_leafs(node.if_true, visited) + _leafs(node.if_false, visited)))
    return l
        

def make_cfg(inst):
    assert inst.kind not in (clang.CursorKind.WHILE_STMT, clang.CursorKind.DO_STMT)
    root = CFGNode()
    cur = root
    if inst.kind == clang.CursorKind.IF_STMT:
        branch_node = CFGBranch()
        branch_node.cond = inst.cond
        cur = cur.connect(branch_node)
        cur.if_true = make_cfg(inst.body)
        cur.if_false = make_cfg(inst.other_body)
        
        after_node = CFGNode()
        l = _leafs(cur.if_true) + _leafs(cur.if_false)
        for x in l:
            x.connect(after_node, join=True)
        cur = after_node
    elif inst.kind == clang.CursorKind.SWITCH_STMT:
        del root
        del cur
        after_node = CFGNode()
        swt = CFGSwitch()    
        swt.cond = inst.cond
        body = inst.body.get_children()
        # Group instructions for each case
        assert body[0].kind in (clang.CursorKind.CASE_STMT, clang.CursorKind.DEFAULT_STMT)
        cases =  []
        case_cond = None
        current_case = []
        for i in body:
            if i.kind in (clang.CursorKind.CASE_STMT, clang.CursorKind.DEFAULT_STMT):
                if current_case:
                    cases.append((case_cond, current_case))
                current_case = []
                current_case.extend(i.body.get_children())
                case_cond = i.case
            else:
                current_case.append(i)
        if current_case:
            cases.append((case_cond, current_case))
        current_case = []
        # End of switch body and grouping

        # Creat the jumps
        for case_cond, inst_list in cases:
            begin = CFGNode()
            cur = begin
            for i in inst_list:
                node = make_cfg(i)
                cur = cur.connect(node)
            # Next node after a case from this Switch statement
            swt.jmps.append((case_cond, begin))
            l = _leafs(cur)
            for x in l:
                x.connect(after_node, join=True)
        return swt
    elif inst.kind == clang.CursorKind.FOR_STMT:
        cur.add(inst.pre)
        branch_node = CFGBranch()
        branch_node.cond = inst.cond
        cur = cur.connect(branch_node)

        body_node = make_cfg(inst.body)
        body_node.add(inst.post)
        body_node.connect(branch_node)

        branch_node.if_true = body_node
        branch_node.if_false = CFGNode()
        cur = branch_node.if_false
    elif inst.kind == BLOCK_OF_CODE:
        for child in inst.get_children():
            node = make_cfg(child)
            cur = cur.connect(node)
            l = _leafs(cur)
            if len(l) == 1:
                cur = l[0]
            else:
                after_node = CFGNode()
                for x in l:
                    x.connect(after_node, join=True)
                cur = after_node
    else:
        cur.add(inst)
    return root
