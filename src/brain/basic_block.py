from instruction import *
from code_pass import Pass
from cfg import CFGJump, CFGNode, Jump, TRUE, FALSE, cfg_leafs

DASH = Literal('-', CODE_LITERAL)
ONE = Literal('1', clang.CursorKind.INTEGER_LITERAL)
TWO = Literal('2', clang.CursorKind.INTEGER_LITERAL)
OTHERWISE = Literal('otherwise', CODE_LITERAL)

def _deep(inst):
    if inst.kind == clang.CursorKind.PAREN_EXPR:
        return _deep(inst.body.children[0])
    elif inst.kind == clang.CursorKind.CSTYLE_CAST_EXPR:
        return _deep(inst.castee.children[0])
    elif inst.kind == clang.CursorKind.BINARY_OPERATOR and inst.op == '=':
        return _deep(inst.rhs.children[0])
    return inst


def inst_is_func_call(inst):
    tmp = _deep(inst)
    if tmp.kind == clang.CursorKind.CALL_EXPR:
        return tmp
    return None


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
        self.boundary = False

    def __str__(self):
        return f'[{self.insts}]'

    def __repr__(self):
        return str(self)

    def is_red(self):
        assert len(self.insts) > 0
        # TODO: I might to fix this in the Instruction class. Maybe an
        # instruction that has a red child, should be red.
        first_inst = self.insts[0]
        if first_inst.is_modified():
            return True
        tmp = _deep(first_inst)
        return first_inst.is_modified()

    def is_func_call(self):
        assert len(self.insts) > 0
        first_inst = self.insts[0]
        tmp = inst_is_func_call(first_inst) is not None
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
        tmp = _deep(inst)
        inst_is_red = inst.is_modified() or tmp.is_modified()
        if inst_is_red:
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

        if inst.is_modified():
            tmp = BasicBlock()
            tmp_inst = Literal('modified code', CODE_LITERAL)
            # print(inst.color, inst.removed)
            tmp_inst.color = inst.color
            tmp.insts.append(tmp_inst)
            A.connect(tmp, join=False)
            A = tmp
        if inst.kind == clang.CursorKind.IF_STMT:
            A.connect(jmp, join=False)
            jmp.cond = inst.cond.children[0]
            br1 = CreateBasicBlockCFG.do(inst.body, self.info).cfg_root
            br2 = CreateBasicBlockCFG.do(inst.other_body, self.info).cfg_root
            jmp.jmps.append(Jump(TRUE, br1, False, likely=inst.likelihood))
            _connect_leafs_to(B, br1)
            if not br2.is_empty():
                tmp = Likelihood.flip(inst.likelihood)
                jmp.jmps.append(Jump(FALSE, br2, False, likely=tmp))
                _connect_leafs_to(B, br2)
            else:
                jmp.jmps.append(Jump(FALSE, B, False))
        elif inst.kind == clang.CursorKind.FOR_STMT:
            pre = CreateBasicBlockCFG.do(inst.pre, self.info).cfg_root
            A.connect(pre, join=False)
            pre.connect(jmp, join=False)
            post = CreateBasicBlockCFG.do(inst.post, self.info).cfg_root
            body = CreateBasicBlockCFG.do(inst.body, self.info).cfg_root
            _connect_leafs_to(post, body)
            tmp_jmp = CFGJump()
            tmp_jmp.cond = DASH
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
            tmp_jmp.cond = DASH
            tmp_jmp.jmps.append(Jump(TRUE, jmp, True))
            _connect_leafs_to(tmp_jmp, body)
        elif inst.kind == clang.CursorKind.DO_STMT:
            body = CreateBasicBlockCFG.do(inst.body, self.info).cfg_root
            A.connect(body, join=False)
            body.connect(jmp, join=False)
            jmp.cond = inst.cond.children[0]
            jmp.jmps.append(Jump(TRUE, body, True))
            jmp.jmps.append(Jump(FALSE, B, False))
        elif inst.kind == clang.CursorKind.SWITCH_STMT:
            A.connect(jmp, False)
            jmp.cond = inst.cond.children[0]
            for sw_case in inst.body.children:
                if sw_case.kind == clang.CursorKind.DEFAULT_STMT:
                    c = OTHERWISE
                else:
                    c = sw_case.case.children[0]
                body = CreateBasicBlockCFG.do(sw_case.body, self.info).cfg_root
                jmp.jmps.append(Jump(c, body, False))
                _connect_leafs_to(B, body)
        else:
            raise Exception('Unexpected type of branching instruction')
        self.cur_block = B

    def _do_process_inst(self, inst, more):
        if inst.kind in BRANCHING_INSTRUCTIONS:
            self._handle_a_branching_inst(inst, more)
        elif inst_is_func_call(inst):
            """
            Transform the CFG as follows.
                [A]--> null
                ===
            to
                [A]-->[Func Call]-->[B]-->null
                                    ===
            """
            A = self.cur_block
            # NOTE: Always create an empty block before functions so we could
            # decide if we want set boundary before or after the function call
            func_call = BasicBlock()
            A.connect(func_call, join=False)
            func_call.add(inst)
            B = BasicBlock()
            func_call.connect(B, join=False)
            self.cur_block = B
        elif inst.kind == ANNOTATION_INST:
            if not inst.is_block_annotation() or not inst.has_children():
                return
            A = self.cur_block
            B = BasicBlock()
            jmp = CFGJump()
            jmp.cond = inst
            body = CreateBasicBlockCFG.do(inst.block, self.info).cfg_root
            jmp.jmps.append(Jump(ONE, body, False))
            jmp.jmps.append(Jump(TWO, B, False))
            A.connect(jmp, False)
            _connect_leafs_to(B, body)
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

            if inst.kind in (clang.CursorKind.RETURN_STMT, TO_USERSPACE_INST):
                self.cur_block.terminal = True

    def process_current_inst(self, inst, more):
        # assert inst.kind in (BLOCK_OF_CODE,), f'Unexpected kind {inst.kind}'
        if inst.kind == BLOCK_OF_CODE:
            for child_inst in inst.get_children():
                self._do_process_inst(child_inst, more)
        else:
            self._do_process_inst(inst, more)
        self.skip_children()
        return inst


def create_basic_block_cfg(prog, info):
    cfg = CreateBasicBlockCFG.do(prog, info).cfg_root
    return cfg
