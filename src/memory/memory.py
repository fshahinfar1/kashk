from memory.mem_entry import MemEntry


__tmp_counter = 0
def __get_mem_id_reference():
    global __tmp_counter
    __tmp_counter += 1
    return __tmp_counter


class Memory:
    __slots__ = ('addr_book',)

    def __init__(self):
        self.addr_book = {}

    def get(self, addr):
        return self.addr_book[addr]

    def alloc(self, region, _type):
        """
        Create a new memory etnry
        """
        _id = __get_mem_id_reference()
        e = MemEntry(_id, region, _type)
        self.addr_book[_id] = e
        return e

    def is_bpf_ptr(slef, entry):
        if not entry.type.is_pointer():
            return False
        pointed_id = entry.value
        pointee = self.addr_book.get(pointed_id)
        return pointee.is_bpf_val()
