from cfg import CFGJump
from brain.basic_block import BasicBlock
from code_pass import Pass


class ExecutionBlock:
    def __init__(self):
        self.paths = []
        self.exp_cost = None


class ExecutionPath:
    counter = 0

    def __init__(self):
        ExecutionPath.counter += 1
        self.id = ExecutionPath.counter
        # this list will contain basic blocks comprising a path. It may also
        # contain some Jump object in case there is a backward jump.
        self.blocks = []

    def add(self, block):
        self.blocks.append(block)

    def __add__(self, other):
        """
        Create a new execution path by extending the current path with the
        other
        """
        assert isinstance(other, ExecutionPath)
        new = ExecutionPath()
        new.blocks = self.blocks + other.blocks
        return new

    def clone(self):
        new = ExecutionPath()
        new.blocks = self.blocks[:]
        return new


class ExtractExecPath(Pass):
    """
    Walks a CFG and prepares a list of different execution paths.
    """
    def __init__(self, info):
        super().__init__(info)

        self._first_node = None
        self.cur_path = ExecutionPath()
        self.paths = []

    def process_current_inst(self, node, more):
        if self._first_node is None:
            self._first_node = node
        if isinstance(node, BasicBlock):
            self.cur_path.add(node)
        elif isinstance(node, CFGJump):
            did_something = False
            cur = self.cur_path
            # Check if this node is a kind of loop ...
            loop_jumps = [j for j in node.jmps if j.forward_loop_branch]
            loop = ExecutionBlock()
            for j in loop_jumps:
                tmp = ExtractExecPath.do(j.target, self.info)
                for branch in tmp.paths:
                    loop.paths.append(branch)
            if len(loop.paths) > 0:
                cur = cur.clone()
                cur.add(loop)
            for j in node.jmps:
                if j.forward_loop_branch:
                    continue
                if j.backward:
                    # Let's not follow the backward links
                    # self.cur_path.add(j)
                    continue
                did_something = True
                # NOTE: I could track the condition for each branch if needed
                tmp = ExtractExecPath.do(j.target, self.info)
                for branch in tmp.paths:
                    path = cur + branch
                    self.paths.append(path)
            # End of a straight track. Do not continue. We are done.
            self.skip_children()
            if did_something:
                self.cur_path = None
        else:
            raise Exception('Encountered unexpected CFG node')
        return node

    def end_current_inst(self, node, more):
        if node == self._first_node:
            # End of processing this CFG
            if self.cur_path is None:
                return
            self.paths.append(self.cur_path)


def extract_exec_paths(cfg, info):
    """
    Extact all execution paths from the given CFG
    @returns a list containing different paths
    """
    tmp = ExtractExecPath.do(cfg, info)
    return tmp.paths
