from contextlib import contextmanager
import clang.cindex as clang
from code_pass import Pass
from log import debug, error
from passes.pass_obj import PassObject
from bpf_code_gen import gen_code

from instruction import Literal

from helpers.instruction_helper import show_insts


MODULE_TAG = '[Complexity]'


def _get_repeat_from_for_loop(inst):
    assert 0, 'This path is incomplete'
    cond = inst.cond.children[0]
    if cond.kind == clang.CursorKind.BINARY_OPERATOR and cond.op in ('<', '=', '>', '>=', '<='):
        lhs = cond.lhs.children[0]
        rhs = cond.rhs.children[0]
        const = lhs if isinstance(lhs, Literal) else (rhs if isinstance(rhs, Literal) else None)
        if const is None:
            return None
        try:
            repeat = int(const.text)
            return repeat
        except:
            pass
        return None
    return None


class MeasureProgramComplexity(Pass):
    @classmethod
    def do(cls, inst, info, more=None):
        """
        Run the pass and return the maximum number of instructions
        """
        obj = super().do(inst, info, more)
        return obj.instruction_count

    def __init__(self, info):
        super().__init__(info)
        self.instruction_count = 0
        self._may_remove = False

    @contextmanager
    def new_inst_counter(self, start=0):
        tmp = self.instruction_count
        self.instruction_count = start
        try:
            yield
        finally:
            self.instruction_count = tmp

    def do_measure(self, block):
        with self.new_inst_counter():
            self.do_pass(block, PassObject())
            count = self.instruction_count
        return count

    def process_current_inst(self, inst, more):
        info = self.info
        if inst.kind == clang.CursorKind.UNARY_OPERATOR:
            # One read, one operation, and one write
            self.instruction_count += 3
        elif inst.kind == clang.CursorKind.BINARY_OPERATOR:
            self.instruction_count += 6
        elif inst.kind == clang.CursorKind.CALL_EXPR:
            # Move each argument to the correct register
            self.instruction_count += len(inst.args)
            #
            func = inst.get_function_def()
            if func is not None and not func.is_empty():
                if func.complexity:
                    self.instruction_count += func.complexity
                    debug(MODULE_TAG, 'func:', func.name, 'inst:',
                            func.complexity)
                else:
                    with self.set_current_func(func):
                        count = self.do_measure(func.body)
                        func.complexity = count
                        debug(MODULE_TAG, 'func:', func.name, 'inst:', count)
                        self.instruction_count += count
            elif inst.name == 'memcpy':
                assert len(inst.args) == 3
                size = inst.args[2]
                repeat = None
                if isinstance(size, Literal):
                    try:
                        repeat = int(size.text)
                    except:
                        pass
                if repeat:
                    # Prepare the source dest pointers (2)
                    # In repeat: Copy (1)
                    # In repeat: Check (1)
                    count = repeat * 2 + 2
                    self.instruction_count += count
                else:
                    error('could not determine the size of memcpy')
                    assert 0, 'This path is dead for now'
            else:
                error('We do not know the implementation of the function what should I do?', inst.name)
        elif inst.kind == clang.CursorKind.IF_STMT:
            count_cond  = self.do_measure(inst.cond)
            count1 = self.do_measure(inst.body)
            count2 = self.do_measure(inst.other_body)
            self.instruction_count += count_cond
            # self.instruction_count += max(count1, count2)
            # The constant is for jump
            self.instruction_count += count1 + count2 + 1
            self.skip_children()
        elif inst.kind == clang.CursorKind.FOR_STMT:
            repeat = inst.repeat
            if repeat is None:
                debug('check if for loop is variable size or not')
                repeat = _get_repeat_from_for_loop(inst)
            if repeat:
                tmp_pre_count  = self.do_measure(inst.pre)
                tmp_cond_count = self.do_measure(inst.cond)
                tmp_post_count = self.do_measure(inst.post)
                tmp_body_count = self.do_measure(inst.body)
                # The constant (2) is for comparing and then jump
                count = tmp_pre_count + repeat * (tmp_cond_count
                                             + tmp_post_count + tmp_body_count + 2)
                text, _ = gen_code([inst,], info)
                # debug(text)
                # debug('loop complexity:', count)
                self.instruction_count += count
            else:
                debug('does not know the upper bound of the loop')
                text, _ = gen_code([inst,], info)
                debug(text)
                debug('-------------------------------------------')
            self.skip_children()
        elif inst.kind in (clang.CursorKind.DO_STMT,
                                clang.CursorKind.WHILE_STMT):
            debug('we do not expect the while statements')
        elif inst.kind == clang.CursorKind.DECL_REF_EXPR:
            self.instruction_count += 1
        elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
            self.instruction_count += 1 + len(inst.owner)
        elif inst.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
            self.instruction_count += 3
        elif inst.kind in (clang.CursorKind.CSTYLE_CAST_EXPR, clang.CursorKind.VAR_DECL, clang.CursorKind.PAREN_EXPR):
            pass
        else:
            self.instruction_count += 1
        # Do not remove any instruction
        return inst


def mitiage_program_comlexity(bpf, info, more):
    count = MeasureProgramComplexity.do(bpf, info, more)
    debug('Main:', count)
    return bpf
