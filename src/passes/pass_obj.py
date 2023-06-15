class PassObject:
    def __init__(self):
        self.lvl = 0
        self.ctx = None
        self.parent_list = None

    def get(self, key, default=None):
        if hasattr(self, key):
            return getattr(self, key)
        return default

    def unpack(self):
        return self.lvl, self.ctx, self.parent_list

    @classmethod
    def pack(self, lvl, ctx, lst):
        new = PassObject()
        new.lvl = lvl
        new.ctx = ctx
        new.parent_list = lst
        return new

    def repack(self, lvl, ctx, lst):
        new = PassObject()
        for name, val in vars(self).items():
            setattr(new, name, val)
        new.lvl = lvl
        new.ctx = ctx
        new.parent_list = lst
        return new
