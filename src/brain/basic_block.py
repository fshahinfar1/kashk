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


class CreateBasicBlockCFG(Pass):
    def __init__(self, info):
        super().__init__(info)
        self.cfg_root = BasicBlock()
        self.cur_block = self.cfg_root

    def _check_same_color(self, inst):
        """
        Check if instruction is the same color as the current basic-block
        """
        assert not self.cur_block.is_empty
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
        jmp = CFGJump()
        B = BasicBlock()
        A.connect(jmp, join=False)
        if inst.kind == clang.CursorKind.IF_STMT:
            jmp.cond = inst.cond.children[0]
            br1 = CreateBasicBlockCFG.do(inst.body, self.info)
            br2 = CreateBasicBlockCFG.do(inst.other_body, self.info)
            assert 0, 'Not implemented yet'
            pass
        elif inst.kind == clang.CursorKind.FOR_STMT:
            jmp.cond = inst.cond.children[0]
            pass
        elif inst.kind == clang.CursorKind.WHILE_STMT:
            jmp.cond = inst.cond.children[0]
            pass
        elif inst.kind == clang.CursorKind.DO_STMT:
            pass
        elif inst.kind == clang.CursorKind.SWITCH_STMT:
            pass

    def _process_a_block_of_code(self, inst, more):
        for child_inst in inst.get_children():
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
        assert inst.kind in (BLOCK_OF_CODE,)
        if inst.kind == BLOCK_OF_CODE:
            self._process_a_block_of_code(inst, more)
        return inst

    def end_current_inst(self, inst, more):
        pass


def create_basic_block_cfg(prog, info):
    pass
