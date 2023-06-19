from instruction import *


class CFG_Edge:
    def __init__(self):
        self.start = None
        self.end = None


class CFG_Block:
    def __init__(self):
        self.body = None
        self.next = None


class CFG_Branch:
    def __init__(self):
        # Left: false
        self.left = None
        # Right: true
        self.right = None
        self.condition = []
