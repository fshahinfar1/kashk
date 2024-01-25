import clang.cindex as clang
from log import *
from instruction import *
from data_structure import *
from bpf_code_gen import gen_code
from passes.passable import PassableObject

TRUE = Literal('True', CODE_LITERAL)
FALSE = Literal('False', CODE_LITERAL)


class Jump:
    def __init__(self, cond, target, backward):
        self.case_cond = cond
        self.target = target
        self.backward = backward

    def __iter__(self):
        yield self.case_cond
        yield self.target


class CFGBaseNode(PassableObject):
    node_id = 0
    def __init__(self):
        super().__init__()
        self.node_id = f'N{CFGBaseNode.node_id}'
        CFGBaseNode.node_id += 1

    def clone(self, children):
        return self


class CFGJump(CFGBaseNode):
    def __init__(self):
        super().__init__()
        self.cond = None
        self.jmps = []

    def get_children_context_marked(self):
        return [(j.target, None)
                    for j in self.jmps
                        if not j.backward]


class CFGNode(CFGBaseNode):
    def __init__(self):
        super().__init__()
        self.insts = []
        self.next = None

    def add(self, inst):
        self.insts.append(inst)

    def connect(self, node, join):
        assert self != node
        assert self.next == None
        if join and isinstance(node, CFGNode):
            if node.next is None and len(node.insts) == 0:
                # discard the other node
                pass
            elif node.next is None:
                # Merge instructions of two nodes
                self.insts.extend(node.insts)
            elif len(node.insts) == 0:
                # Remove empty other
                self.next = node.next
            else:
                # node.next is not None and node.insts has code
                self.next = node.next
                self.insts.extend(node.insts)
            return self

        self.next = node
        return node

    def is_empty(self):
        return len(self.insts) == 0 and self.next is None

    def get_children_context_marked(self):
        if self.next is None:
            return []
        return [(self.next, None), ]


class HTMLWriter:
    def __init__(self):
        self.used_ids = set()

    def _node_to_html(self, node, info):
        if node is None:
            return ''

        if node.node_id in self.used_ids:
            return ''
        self.used_ids.add(node.node_id)

        if isinstance(node, CFGNode):

            insts = [f'<p class="codetext">"{gen_code([i], info)[0]}"</p>' for i in node.insts]
            text = [
                    f'<div id={node.node_id} class="node">',
                    f'<p class="nodeid">id: {node.node_id}</p>',
                    f'<p class="nodeid">to: {node.next.node_id if node.next is not None else "-"}</p>',
                    ] + insts + ['</div>',]
            text = '\n'.join(text)
            text += '\n' + self._node_to_html(node.next, info)
            return text
        if isinstance(node, CFGJump):
            cases = []
            other_nodes_text = []
            for cond, n in node.jmps:
                cond_text, _ = gen_code([cond,], info)
                cases.append(f'<p>on "{cond_text}": {n.node_id if n.node_id else "-"}</p>')
                other_nodes_text.append(self._node_to_html(n, info))
            cond_text = gen_code([node.cond,], info)[0]
            insts = [ f'<p class="nodeid">id: {node.node_id}</p>',] + cases + [f'<p class="codetext">Switch on "{cond_text}"</p>', ]
            text = [f'<div id={node.node_id} class="node">',] + insts + ['</div>',]
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
    if visited is None:
        visited = set()
    if node is None or node.node_id in visited:
        return []
    visited.add(node.node_id)
    if isinstance(node, CFGNode):
        if node.next is None:
            return [node]
        ptr = node
        while isinstance(ptr, CFGNode):
            if ptr.next is not None:
                if ptr.next.node_id in visited:
                    if isinstance(ptr.next, CFGJump):
                        return []
                    else:
                        raise Exception('Looping back to a normal node?!')
                ptr = ptr.next
                visited.add(ptr.node_id)
            else:
                return [ptr]
        node = ptr

    if isinstance(node, CFGJump):
        """
        Gather all leaf nodes from all cases. Remove duplicates and return the
        results.
        """
        leaf_nodes = set()
        for _, n in node.jmps:
            for x in _leafs(n, visited):
                leaf_nodes.add(x)
        l = list(leaf_nodes)
        return l

    assert 0


def make_cfg(inst):
    assert inst.kind not in (clang.CursorKind.WHILE_STMT,
            clang.CursorKind.DO_STMT, clang.CursorKind.GOTO_STMT)
    root = CFGNode()
    cur = root
    if inst.kind == clang.CursorKind.IF_STMT:
        jmp = CFGJump()
        jmp.cond = inst.cond.children[0]
        cur = cur.connect(jmp, join=False)
        if_true = make_cfg(inst.body)
        jmp.jmps.append(Jump(TRUE, if_true, False))
        after_node = CFGNode()
        l = _leafs(if_true)
        if inst.other_body.has_children():
            if_false = make_cfg(inst.other_body)
            jmp.jmps.append(Jump(FALSE, if_false, False))
            l += _leafs(if_false)
        else:
            jmp.jmps.append(Jump(FALSE, after_node, False))
        for x in l:
            x.connect(after_node, join=False)
        cur = after_node
    elif inst.kind == clang.CursorKind.SWITCH_STMT:
        swt = CFGJump()
        swt.cond = inst.cond.children[0]
        cur = cur.connect(swt, join=False)
        body = inst.body.get_children()
        after_node = CFGNode()
        for case_inst in body:
            assert case_inst.kind in (clang.CursorKind.CASE_STMT,
                    clang.CursorKind.DEFAULT_STMT)
            case_cond = case_inst.case.children[0]
            inst_list = case_inst.body.get_children()
            cur = begin = CFGNode()
            for i in inst_list:
                node = make_cfg(i)
                cur.connect(node, join=True)
            l = _leafs(begin)
            for x in l:
                x.connect(after_node, join=True)
            swt.jmps.append(Jump(case_cond, begin, False))
    elif inst.kind == clang.CursorKind.FOR_STMT:
        cur.insts.extend(inst.pre.children)
        jmp = CFGJump()
        jmp.cond = inst.cond.children[0]
        cur = cur.connect(jmp, join=False)
        body_node = make_cfg(inst.body)
        last_node = CFGNode()
        last_node.insts.extend(inst.post.children)
        after_node = CFGNode()
        jmp.jmps.append(Jump(TRUE, body_node, False))
        jmp.jmps.append(Jump(FALSE, after_node, False))
        for x in _leafs(body_node):
            x.connect(last_node, join=False)
        backward = CFGJump()
        backward.cond = Literal('backward-jump', CODE_LITERAL)
        backward.jmps.append(Jump(TRUE, jmp, True))
        last_node.connect(backward, join=False)
        cur = after_node
    elif inst.kind == BLOCK_OF_CODE:
        for child in inst.get_children():
            node = make_cfg(child)
            cur = cur.connect(node, join=True)
            l = _leafs(cur)
            if len(l) == 1:
                cur = l[0]
            else:
                after_node = CFGNode()
                for x in l:
                    x.connect(after_node, join=True)
                cur = after_node
    else:
        # TODO: the terminal nodes should be marked
        cur.add(inst)
    return root
