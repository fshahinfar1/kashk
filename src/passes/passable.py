class PassableObject:
    def __init__(self):
        self.kind = None
        self.node_id = None

    def get_children_context_marked(self):
        raise Exception('Not implemented')

    def clone(self, children):
        raise Exception('Not implemented')
