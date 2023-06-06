def _get_rev_children(cursor, lst, depth=0):
    children = list(cursor.get_children())
    children.reverse()
    for c in children:
        lst.append((c, depth))


class DFSPass:
    def __init__(self, cursor, inside=False):
        if inside:
            self.q = []
            _get_rev_children(cursor, self.q, 0)
        else:
            self.q = [(cursor, 0)]
        self._if_deep = []

    def enque(self, cursor, depth):
        """
        The cursor would be processed immediatly the next time user calls next.
        """
        self.q.append((cursor, depth))

    def go_deep(self):
        self.q.extend(self._if_deep)

    def __iter__(self):
        return self

    def __next__(self):
        if not self.q:
            raise StopIteration()
        cursor, depth = self.q.pop()

        self._if_deep.clear()
        _get_rev_children(cursor, self._if_deep, depth + 1)

        return cursor, depth
