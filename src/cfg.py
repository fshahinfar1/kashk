import clang.cindex as clang
from log import *
from instruction import *
from data_structure import *
from bpf_code_gen import gen_code

node_id = 0
class CFGBranch:
    def __init__(self):
        global node_id
        self._id = node_id
        node_id += 1

        self.cond = None
        self.if_true = None
        self.if_false = None

class CFGNode:
    def __init__(self):
        global node_id
        self._id = node_id
        node_id += 1

        self.insts = []
        self._next = None

    def add(self, inst):
        self.insts.append(inst)

    def next(self, node):
        assert self._next == None
        self._next = node
        return node

has_generated = set()
def _node_to_html(node, info):
    if node is None:
        return ''

    if node._id in has_generated:
        return ''
    has_generated.add(node._id)

    if isinstance(node, CFGNode):
        
        insts = [f'<p>"{gen_code([i], info)[0]}"</p>' for i in node.insts]
        text = [
                f'<div id={node._id} class="node">',
                f'<p class="nodeid">id: {node._id}</p>',
                f'<p class="nodeid">to: {node._next._id if node._next is not None else "-"}</p>',
                ] + insts + ['</div>',]
        text = '\n'.join(text)
        text += '\n' + _node_to_html(node._next, info)
        return text
    if isinstance(node, CFGBranch):
        cond_text = gen_code(node.cond, info)[0]
        insts = [
                f'<p class="nodeid">id: {node._id}</p>',
                f'<p>Branch on "{cond_text}"</p>',
                f'<p>if_true: {node.if_true._id if node.if_true else "-"}</p>',
                f'<p>if_false: {node.if_false._id if node.if_false else "-"}</p>',
                ]
        text = [f'<div id={node._id} class="node">',] + insts + ['</div>',]
        text = '\n'.join(text)
        text += '\n' + _node_to_html(node.if_true, info)
        text += '\n' + _node_to_html(node.if_false, info)
        return text
    raise Exception('Unexpected!')

def cfg_to_html(node, info):
    text = _node_to_html(node, info)
    res = [
        '<!DOCTYPE html>',
        '<head>',
        '<title>CFG</title>',
        '<style>',
        '.node { border: black 1pt solid; display: inline-block; padding: 2pt};'
        '</style>',
        '</head>',
        '<body>',
        text,
        '</body>',
        ]
    return '\n'.join(res)


def _leafs(node):
    if node is None:
        return []

    if isinstance(node, CFGNode):
        if node._next is None:
            return [node]
        ptr = node
        while isinstance(ptr, CFGNode):
            if ptr._next is not None:
                ptr = ptr._next
            else:
                return [ptr]
        node = ptr
    
    # node is CFGBranch object
    assert isinstance(node, CFGBranch)
    l = list(set(_leafs(node.if_true) + _leafs(node.if_false)))
    for x in l:
        print(x, x._next)
        assert x._next is None
    return l
        

def make_cfg(inst):
    assert inst.kind not in (clang.CursorKind.SWITCH_STMT, clang.CursorKind.CASE_STMT)
    root = CFGNode()
    cur = root
    if isinstance(inst, ControlFlowInst):
        branch_node = CFGBranch()
        branch_node.cond = inst.cond
        cur = cur.next(branch_node)
        cur.if_true = make_cfg(inst.body)
        cur.if_false = make_cfg(inst.other_body)
        
        after_node = CFGNode()
        l = _leafs(cur.if_true) + _leafs(cur.if_false)
        for x in l:
            x.next(after_node)
        cur = after_node
    elif isinstance(inst, ForLoop):
        cur.add(inst.pre)
        branch_node = CFGBranch()
        branch_node.cond = inst.cond
        cur = cur.next(branch_node)

        body_node = make_cfg(inst.body)
        body_node.add(inst.post)

        branch_node.if_true = body_node
        branch_node.if_false = CFGNode()
        cur = branch_node.if_false
    elif inst.kind == BLOCK_OF_CODE:
        for child in inst.get_children():
            node = make_cfg(child)
            cur = cur.next(node)
            l = _leafs(cur)
            if len(l) == 1:
                cur = l[0]
            else:
                after_node = CFGNode()
                for x in l:
                    x.next(after_node)
                cur = after_node
    else:
        cur.add(inst)
    return root
