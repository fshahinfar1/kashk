class LinkedExecPath:
    """
    Create an execution path by linking sequence of instructions
    """
    __slots__ = ('next', 'prev', 'insts')

    def __init__(self):
        self.next = None
        self.prev = None
        self.insts = None

    def __len__(self):
        nxt_len = len(self.next) if self.next else 0
        return len(self.insts) + nxt_len

    def __iter__(self):
        return LinkedExecPathIter(self)


class LinkedExecPathIter:
    """
    An iterator fascilating the traversal of a execution path
    """
    __slots__ = ('path', 'local_length', 'cur_index')

    def __init__(self, path: LinkedExecPath):
        self._prepare_with(path)

    def _prepare_with(self, path):
        self.path = path
        self.local_length = len(self.path.insts)
        self.cur_index = 0

    def __next__(self):
        while self.cur_index >= self.local_length:
            nxt = self.path.next 
            if nxt is None:
                raise StopIteration()
            else:
                self._prepare_with(nxt)

        item = self.path.insts[self.cur_index]
        self.cur_index += 1
        return item
