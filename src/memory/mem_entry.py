from my_type import MyType


class MemEntry:
    __slots__ = ('id', 'val', 'region', 'type', 'associated_sym')

    REGION_STK = 100
    REGION_MAP = 101
    REGION_CTX = 102
    REGION_NO_WHERE = 103

    def __init__(self, _id, region, _type: MyType):
        self.id = _id
        self.val = None 
        self.region = region
        self.type = _type # type of variable the memory was created for
        # type of object it has assigned to. It makes more sense for pointers
        # e.g., a char pointer to an array.
        self.val_type = None
        self.associated_sym = None
        assert isinstance(_type, MyType)

    def get_ref(self):
        return self.id

    def is_bpf_val(self):
        return self.region == MemEntry.REGION_CTX
