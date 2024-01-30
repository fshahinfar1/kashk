from contextlib import contextmanager
from data_structure import *
from instruction import *
from passes.pass_obj import PassObject
from passes.clone import clone_pass

PARENT_INST = 1000

# TODO: support declare_at_top_of_func
# TODO: support After objects (adding some instructions after the current
#                               instruction being investigated)


ignore_these_parents = (
        clang.CursorKind.CSTYLE_CAST_EXPR,
        clang.CursorKind.PAREN_EXPR,
        BLOCK_OF_CODE,
    )

class Pass:
    __slots__ = ('current_function', 'visited_functions', 'cb_ref', 'info',
            'result', '_may_remove', '_skip_children', '_visited_ids')
    @classmethod
    def do(cls, inst, info, more=None, func=None, **kwargs):
        obj = cls.__new__(cls)
        obj.__init__(info)
        for k, v in kwargs.items():
            setattr(obj, k, v)
        res = None
        with obj.set_current_func(func):
            if more is None:
                more = PassObject()
            res = obj.do_pass(inst, more)
        obj.result = res
        return obj

    def __init__(self, info):
        self.current_function = None
        self.visited_functions = set()
        self.cb_ref = CodeBlockRef()
        self.info = info
        self.result = None
        self._may_remove = False
        self._skip_children = False
        self.parent_stack = CodeBlockRef()
        self._visited_ids = set()

    @property
    def parent_inst(self):
        """
        Returns the parent instruction of the currently investigated
        instruction.

        The parent instruction is the one this instruction is its child.
        """
        return self.parent_stack.get(PARENT_INST)

    def get_valid_parent(self):
        at = 0
        parent = self.parent_stack.get2(PARENT_INST, at)
        while parent is not None:
            if parent.kind not in ignore_these_parents:
                # found a good parent instruction
                break
            at += 1
            parent = self.parent_stack.get2(PARENT_INST, at)
        return parent

    @contextmanager
    def set_current_func(self, func, change_scope=True):
        """
        Change scope and update current_function value
        """
        if func is not None and change_scope:
            with self.info.sym_tbl.with_func_scope(func.name):
                tmp = self.current_function
                self.current_function = func
                try:
                    yield func
                finally:
                    self.current_function = tmp
        else:
            tmp = self.current_function
            self.current_function = func
            try:
                yield func
            finally:
                self.current_function = tmp

    def skip_children(self):
        self._skip_children = True

    def process_current_inst(self, inst, more):
        """
        When a new instruction is observed
        """
        return inst

    def end_current_inst(self, inst, more):
        """
        When current instructionis finished processing
        """
        return inst

    def do_pass(self, inst, more):
        info = self.info
        lvl, ctx, parent_list = more.unpack()
        new_children = []
        with self.cb_ref.new_ref(ctx, parent_list):
            tmp = self.process_current_inst(inst, more)
            if inst.node_id is not None:
                self._visited_ids.add(inst.node_id)
            inst = tmp
            if inst is None:
                assert self._may_remove, 'This pass is not allowed to remove instructions'
                return None
            if self._skip_children:
                self._skip_children = False
                new_inst = clone_pass(inst)
                return new_inst
            # Continue deeper
            parent = inst if inst.kind != BLOCK_OF_CODE else self.parent_inst
            with self.parent_stack.new_ref(PARENT_INST, parent):
                for child, tag in inst.get_children_context_marked():
                    if isinstance(child, list):
                        new_child = []
                        for i in child:
                            obj = PassObject.pack(lvl+1, tag, new_child)
                            new_inst = self.do_pass(i, obj)
                            if new_inst is not None:
                                new_child.append(new_inst)
                    else:
                        obj = PassObject.pack(lvl+1, tag, parent_list)
                        new_child = self.do_pass(child, obj)
                        if new_child is None:
                            assert self._may_remove, 'This pass is not allowed to remove instructions'
                            return None
                    new_children.append(new_child)
        new_inst = self.end_current_inst(inst, more)
        if inst is None:
            assert self._may_remove, 'This pass is not allowed to remove instructions'
            return None
        new_inst = inst.clone(new_children)
        return new_inst
