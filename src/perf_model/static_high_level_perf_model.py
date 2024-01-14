from code_pass import Pass, PARENT_INST
from instruction import *
from data_structure import *
from log import debug, error
from utility import indent
from bpf_code_gen import gen_code

MODULE_TAG = '[Static Perf Model]'

ignore_these_parents = (
        clang.CursorKind.CSTYLE_CAST_EXPR,
        clang.CursorKind.PAREN_EXPR,
        BLOCK_OF_CODE,
    )


_model_param_counter = 0
def _get_new_param():
    global _model_param_counter
    _model_param_counter += 1
    return f'N{_model_param_counter}'


class PerfStats:
    LOAD = 'load'
    STORE = 'store'
    ALU_OP = 'alu_op'
    JUMP = 'jmp'


class StaticHighLevelPerfModel:
    def __init__(self):
        """
        This class structures the interesting perf stats for a region of the
        code. The constant (non-variable) count of each stat would be
        accumulated in stats dictionary. For the cases with variability (i.e.,
        loops) there is a parameter associated with a sub-model (of the same
        class type).

        When evaluating the model, user provides the value of the parameter
        which would be multiplied with the evaluation result of sub-model.
        """
        self.stats = {}
        self.internal = []
        self._clear_stats()

    def _clear_stats(self):
        """
        Initialize all the statistic counters to zero
        """
        for k, v in vars(PerfStats).items():
            if k.startswith('__'):
                continue
            self.stats[v] = 0

    def _increment(self, stat, value=1):
        self.stats[stat] += value

    def _add_parametric_measure(self, name, model):
        tmp = (name, model)
        self.internal.append(tmp)

    def _extend(self, other):
        """
        Add the results from another model to this model. The add opertaion is
        defined as accumulating the stats and parameters.
        """
        for k, v in other.stats.items():
            self.stats[k] += v
        self.internal.extend(other.internal)

    def evalutate(self, **kwargs):
        """
        Evaluate the model, receive the variables from the kwargs
        """
        pass

    def dump(self):
        lines = []
        for param, sub_model in self.internal:
            sub = sub_model.dump()
            sub = indent(sub)
            txt = f'{param} x {sub} +\n'
            lines.append(txt)
        const = str(self.stats)
        res = '\n'.join(lines) + '\n' + const
        return res


class GenStaticHighLevelPerfModelPass(Pass):
    """
    This pass estimates the performance of program.
    1- It takes a static-analysis approach (no dynamic execution)
    2- It only analyses the source code (no binary inspection)

    The implementation in this model is inspired by PBound paper.  NOTE: PBound
    is assigning the stats to the nodes of the AST, this can provided fine
    grain information about costs for each region of the code. I am not doing
    this. Do I need it?
    """

    def __init__(self, info):
        super().__init__(info)
        self.processing_bin_op = []
        self.model = StaticHighLevelPerfModel()

    def _increment(self, stat, value=1):
        self.model._increment(stat, value)

    def _get_valid_parent(self):
        at = 0
        parent = self.parent_stack.get2(PARENT_INST, at)
        while parent is not None:
            if parent.kind not in ignore_these_parents:
                # found a good parent instruction
                break
            at += 1
            parent = self.parent_stack.get2(PARENT_INST, at)
        return parent

    def _deref_memory(self, inst):
        parent = self._get_valid_parent()
        tmp, _ = gen_code([inst,], self.info)
        pre = (parent is not None and
                parent.kind == clang.CursorKind.BINARY_OPERATOR and
                parent.op in BinOp.ASSIGN_OP)
        is_a_store = (pre and inst in parent.lhs)

        # NOTE: Instruction is an array-subscription/unary_op. Its type would
        # be the type of an element.. we get its size (bytes) in the memory.

        # TODO: there is a chance that I mixed up when implementing the
        # ArrayAccess class and in some cases I return the array_type instead
        # of element_type. If this is the case fix the issue there.

        el_size = inst.type.mem_size
        if is_a_store:
            self._increment(PerfStats.STORE, el_size)
        else:
            # The deref is not in the LHS of an assignment operation so it is a
            # memory LOAD
            self._increment(PerfStats.LOAD, el_size)

    def end_current_inst(self, inst, more):
        if inst.kind == clang.CursorKind.BINARY_OPERATOR:
            # we finished process the binary operator
            self.processing_bin_op.pop()

    def _handle_loop(self, inst, more):
        # First understand how complex is it to check the loop condition
        if isinstance(inst, ForLoop):
            tmp = GenStaticHighLevelPerfModelPass.do(inst.cond, self.info)
            loop_check = tmp.model
            tmp = GenStaticHighLevelPerfModelPass.do(inst.post, self.info)
            loop_check._extend(tmp.model)
        else:
            tmp = GenStaticHighLevelPerfModelPass.do(inst.cond, self.info)
            loop_check = tmp.model

        N = _get_new_param()
        tmp_text, _ = gen_code([inst,], self.info)
        debug('Parameter:', N, 'is for', tmp_text, tag=MODULE_TAG)
        body = inst.body
        inner_block = GenStaticHighLevelPerfModelPass.do(body, self.info)
        inner_model = inner_block.model
        # Count one jump for each iteration of the loop
        inner_model._increment(PerfStats.JUMP)
        # Also add the cost of checking the condition
        inner_model._extend(loop_check)
        # Add as a parametric sub-model
        self.model._add_parametric_measure(N, inner_model)
        self.skip_children()

    def _handle_func(self, inst, more):
        func = inst.get_function_def()
        if func is None or func.is_empty():
            return
        if func.perf_model is None:
            body = func.body
            obj = GenStaticHighLevelPerfModelPass.do(body, self.info, func=func)
            func.perf_model = obj.model
        self.model._extend(func.perf_model)

    def process_current_inst(self, inst, more):
        tag = more.ctx

        if inst.kind == ANNOTATION_INST:
            # Just ignore annotation instruction.
            return inst
        elif inst.kind == clang.CursorKind.DECL_REF_EXPR:
            # This is just a variable reference. Assume they all fit on the
            # register (same as PBound). The pointer reads and array reads need
            # derefrencing. They are counted as memory operations.
            return inst
        elif inst.kind == clang.CursorKind.MEMBER_REF_EXPR:
            # Check if the member operation is derefrencing a pointer
            owner = inst.owner[-1]
            assert isinstance(owner, Ref)
            if not owner.type.is_mem_ref():
                return inst
            # Load this number of bytes from memory
            tmp, _ = gen_code([inst,], self.info)
            if inst.type.is_array():
                # The mem_size returns the size of memory region allocated for
                # the variable. In the case of arrays, it is the total size of
                # the array. When referecing an array member, we are not
                # copying that amount of data, it is just getting address of
                # its first member.

                # Getting address does not neccessary require load/store. it
                # must be the same as `&' operator.
                load_size = 0
                return inst
            else:
                load_size = inst.type.mem_size
            self._increment(PerfStats.LOAD, load_size)
            return inst
        elif inst.kind == clang.CursorKind.ARRAY_SUBSCRIPT_EXPR:
            self._deref_memory(inst)
            return inst
        elif inst.kind == clang.CursorKind.UNARY_OPERATOR:
            if inst.op == '*':
                # it is derefrencing a pointer, check if it is a LOAD or a
                # STORE
                self._deref_memory(inst)
                return inst
            elif inst.op == '&':
                # we are getting the address of something, does not matter what
                # that thing is, there is no load/store operation.
                self.skip_children()
                return inst
            elif inst.op in (*UnaryOp.BIT_OPS, *UnaryOp.BOOL_OPS,
                    *UnaryOp.ARITH_OPS, ):
                self._increment(PerfStats.ALU_OP)
        elif inst.kind == clang.CursorKind.BINARY_OPERATOR:
            self.processing_bin_op.append(inst)
            if inst.op in (*BinOp.REL_OP, *BinOp.ARITH_OP, *BinOp.BIT_OP,
                    *BinOp.LOGICAL_OP):
                self._increment(PerfStats.ALU_OP)
            elif inst.op in BinOp.ASSIGN_OP:
                # NOTE: The LOAD/STORE are counted during derefrencing, so we
                # should not worry about it here

                # Check for syntax suger (e.g., x += 1)
                if inst.op == '=':
                    return inst
                self._increment(PerfStats.ALU_OP)
        elif inst.kind in MAY_HAVE_BACKWARD_JUMP_INSTRUCTIONS:
            self._handle_loop(inst, more)
            return inst
        elif inst.kind == clang.CursorKind.CALL_EXPR:
            self._handle_func(inst, more)
            return inst
        elif inst.kind == clang.CursorKind.IF_STMT:
            self._increment(PerfStats.JUMP)
            return inst
        elif inst.kind == clang.CursorKind.SWITCH_STMT:
            # There will be a jump to one of the cases
            self._increment(PerfStats.JUMP)
            return inst
        return inst


def gen_static_high_level_perf_model(inst, info, more=None):
    obj = GenStaticHighLevelPerfModelPass.do(inst, info)
    return obj.model
