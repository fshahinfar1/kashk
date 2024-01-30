from instruction import *
from code_pass import Pass
from cfg import CFGJump, CFGNode, Jump, TRUE, FALSE, cfg_leafs


class BasicBlock(CFGNode):
    """
    It is a kind of CFG node, which has some attributes :)
    """
    counter = 0
    def __init__(self):
        super().__init__()
        BasicBlock.counter += 1
        self.id = BasicBlock.counter
        # Map a path id to a cost value. Cost of reaching this block when
        # following the given path
        self.cost_book = {}
        self.expected_cost = 0
        self.terminal = False
    
    def is_red(self):
        assert len(self.insts) > 0
        first_inst = self.insts[0]
        return first_inst.is_modified()

    def is_func_call(self):
        assert len(self.insts) > 0
        first_inst = self.insts[0]
        tmp = first_inst.kind == clang.CursorKind.CALL_EXPR
        if tmp:
            assert len(self.insts) == 1, 'Each basic block mut have at most one function call'
        return tmp


def _connect_leafs_to(target, *args):
    """
    Find the leafs of given CFG and connect them to the target node
    """
    for cfg in args:
        assert isinstance(cfg, CFGNode)
        leafs = cfg_leafs(cfg)
        for l in leafs:
            if l.terminal:
                continue
            l.connect(target, join=False)


class CreateBasicBlockCFG(Pass):
    def __init__(self, info):
        super().__init__(info)
        self.cfg_root = BasicBlock()
        self.cur_block = self.cfg_root

    def _check_same_color(self, inst):
        """
        Check if instruction is the same color as the current basic-block
        """
        assert not self.cur_block.is_empty()
        is_red = self.cur_block.is_red()
        if inst.is_modified():
            return is_red
        else:
            return not is_red

    def _handle_a_branching_inst(self, inst, more):
        """
        Transform the CFG as follows.
            [A]--> null
            ===
        to
            [A] 
             |
             v
            <Branch> +-> (Recursivly Generate CFG for branch 1) --
                     |                                            \
                     +-> (Recursivly Generate CFG for branch 2) ----> [B] --> (Rest of the CFG)
                     |                                            
                     +-> ... --> [TERMINAL]

        NOTE: the CFG may terminate in a branch. That means some branches will
        not continue to the rest of CFG.
        """
        A = self.cur_block
        B = BasicBlock()
        jmp = CFGJump()
        if inst.kind == clang.CursorKind.IF_STMT:
            A.connect(jmp, join=False)
            jmp.cond = inst.cond.children[0]
            br1 = CreateBasicBlockCFG.do(inst.body, self.info).cfg_root
            br2 = CreateBasicBlockCFG.do(inst.other_body, self.info).cfg_root
            jmp.jmps.append(Jump(TRUE, br1, False))
            jmp.jmps.append(Jump(FALSE, br2, False))
            _connect_leafs_to(B, br1, br2)
        elif inst.kind == clang.CursorKind.FOR_STMT:
            pre = CreateBasicBlockCFG.do(inst.pre, self.info).cfg_root
            A.connect(pre, join=False)
            pre.connect(jmp, join=False)
            post = CreateBasicBlockCFG.do(inst.post, self.info).cfg_root
            body = CreateBasicBlockCFG.do(inst.body, self.info).cfg_root
            _connect_leafs_to(post, body)
            tmp_jmp = CFGJump()
            tmp_jmp.jmps.append(Jump(TRUE, jmp, True))
            _connect_leafs_to(tmp_jmp, post)
            jmp.cond = inst.cond.children[0]
            jmp.jmps.append(Jump(TRUE, body, False))
            jmp.jmps.append(Jump(FALSE, B, False))
        elif inst.kind == clang.CursorKind.WHILE_STMT:
            A.connect(jmp, join=False)
            jmp.cond = inst.cond.children[0]
            body = CreateBasicBlockCFG.do(inst.body, self.info).cfg_root
            jmp.jmps.append(Jump(TRUE, body, False))
            jmp.jmps.append(Jump(FALSE, B, False))
            tmp_jmp = CFGJump()
            tmp_jmp.jmps.append(Jump(TRUE, jmp, True))
            body.connect(tmp_jmp)
        elif inst.kind == clang.CursorKind.DO_STMT:
            body = CreateBasicBlockCFG.do(inst.body, self.info).cfg_root
            A.connect(body, join=False)
            body.connect(jmp, join=False)
            jmp.cond = inst.cond.children[0]
            jmp.jmps.append(Jump(TRUE, body, True))
            jmp.jmps.append(Jump(FALSE, B, False))
        elif inst.kind == clang.CursorKind.SWITCH_STMT:
            jmp.cond = inst.cond.children[0]
            for sw_case in inst.body.children:
                c = sw_case.case.children[0]
                body = CreateBasicBlockCFG.do(sw_case.body, self.info).cfg_root
                jmp.jmps.append(Jump(c, body, False))
                _connect_leafs_to(B, body)
        self.cur_block = B

    def _do_process_inst(self, inst, more):
        if inst.kind in BRANCHING_INSTRUCTIONS: 
            self._handle_a_branching_inst(inst, more)
        elif inst.kind == clang.CursorKind.CALL_EXPR:
            """
            Transform the CFG as follows.
                [A]--> null
                ===
            to
                [A]-->[Func Call]-->[B]-->null
                                    ===
            """
            A = self.cur_block
            func_call = BasicBlock()
            func_call.add(inst)
            A.connect(func_call, join=False)
            B = BasicBlock()
            func_call.connect(B, join=False)
            self.cur_block = B
        else:
            if self.cur_block.is_empty() or self._check_same_color(inst):
                # If current block is empty or has same color as the
                # instruction, we can add this instruction to this block.
                self.cur_block.add(inst)
            else:
                # Otherwise, Create a new block for this instruction.
                A = self.cur_block
                B = BasicBlock()
                B.add(inst)
                A.connect(B, join=False)
                self.cur_block = B

            if inst.kind == clang.CursorKind.RETURN_STMT:
                self.cur_block.terminal = True

    def process_current_inst(self, inst, more):
        # assert inst.kind in (BLOCK_OF_CODE,), f'Unexpected kind {inst.kind}'
        if inst.kind == BLOCK_OF_CODE:
            for child_inst in inst.get_children():
                self._do_process_inst(child_inst, more)
        else:
            self._do_process_inst(inst, more)
        return inst


def create_basic_block_cfg(prog, info):
    cfg = CreateBasicBlockCFG.do(prog, info).cfg_root
    return cfg
