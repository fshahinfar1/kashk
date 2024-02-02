class PassableObject:
    __slots__ = ('kind', 'node_id', 'ignore')
    def __init__(self):
        self.kind = None
        self.node_id = None
        self.ignore = False

    def get_children_context_marked(self):
        raise Exception('Not implemented')

    def clone(self, children):
        raise Exception('Not implemented')
