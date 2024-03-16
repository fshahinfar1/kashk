import clang.cindex as clang
import instruction
from log import debug
from instruction import *
from data_structure import *
from passes.code_pass import Pass
from passes.clone import clone_pass
from helpers.instruction_helper import show_insts



MODULE_TAG = "[Create Failure Paths]"


_for_debuging_assigned_failure_numbers = set()


__failure_path_func_book = {}
def _get_fail_path_func_counter(path_id):
    x = __failure_path_func_book.get(path_id, 0)
    __failure_path_func_book[path_id] = x + 1
    return x


__fail_counter = 0
def _get_fail_counter():
    global __fail_counter
    __fail_counter += 1
    return __fail_counter


class GatherRestInstruction(Pass):
    """
    WHAT IS THIS CODE DOING:

    Given a AST and a target instruction, find the instruction in the tree and
    gather it along with instructions coming after that. Gathering will
    continue until end of the block of code holding the target instruction.
    If the target instruction is not in a direct block of code (e.g, is an
    argument), move the target to its first parent that directly resides in a
    block of code.
    """
    def __init__(self, info):
        super().__init__(info)
        self.found = False
        self.gathered = []
        self.target = None
        self.target_parent = None
        self.terminate = False

    def process_current_inst(self, inst, more):
        if self.terminate:
            self.skip_children()
            return inst

        if not self.found and inst == self.target:
            self.target = None
            self.found = True

        if not self.found:
            return inst

        if more.ctx != BODY:
            # Let's find the parent instruction, it should happen while
            # recursion is returning toward the root (end_current_inst)
            self.target_parent = self.parent_inst
            assert self.target_parent is not None
            self.found = False
        else:
            self.gathered.append(inst)

        self.skip_children()
        return inst

    def end_current_inst(self, inst, more):
        if self.terminate:
            self.skip_children()
            return inst

        if self.found:
            if inst.kind == BLOCK_OF_CODE:
                self.terminate = True
        else:
            if self.target_parent is None:
                return inst
            if self.target_parent != inst:
                return inst
            if more.ctx == BODY:
                self.found = True
                self.target_parent = None
                self.gathered.append(inst)
            else:
                # Continue looking for the parent
                self.target_parent = self.parent_inst
        return inst



class FindFailurePaths(Pass):
    """
    WHAT IS THIS CODE DOING:

    Walk the AST. When encounter a fallback point (TO_USERSPACE_INST), gather
    all the instructions that are needed to completely process the request
    until the end.

    There are 4 base cases which can be mixed together.
        i)   The fallback happens inside a sequential block of code
        ii)  It happens inside a branch (if-else, switch-case)
        iii) It happens inside a loop
        iv)  It happens as execution of a function call

    * There is a complication because the fallback points are in a different AST
    than the one we are gathering instructions from.
    """
    def __init__(self, info):
        super().__init__(info)
        self.failure_paths = {}
        self.new_declarations = []
        self.terminate = False

    def get_rest(self, inst):
        """
        Get the rest of the instruction in this block
        @param inst: current instruction
        """
        name = '[[main]]' if self.current_function is None else self.current_function.name
        ast = self.info.original_ast[name]
        target = inst.original
        tmp = GatherRestInstruction.do(ast, self.info, target=target)
        # debug('found:', tmp.found, 'looking:', target, tag=MODULE_TAG)
        # show_insts(ast)
        return tmp.gathered

    def _handle_branch(self, inst, b, include_current_inst):
        """
        If there is a failure in a branch, gather instructions after the
        failure point in the branch and prepend them to the remaining
        instructions of current path.

        @param inst: current instruction
        @param b: the branch we are want to analyze
        @param include_current_inst: (used in loops) consider current
            instruction as part of the rest of instruction to be evaluated.
        """
        tmp = FindFailurePaths.do(b, self.info, func=self.current_function)
        if len(tmp.failure_paths) == 0:
            # did not failed
            return

        self.new_declarations.extend(tmp.new_declarations)
        is_extra = inst.original == b.original
        if is_extra:
            assert inst.is_modified(), inst
            # I am assuming this branch was added (not just changed).
            # Make sure this assumption is correct.
            # Due to this assumption, I deduce that the original AST would not
            # experience a branch. Meaning we do not need to gather more
            # instructions.
            # (It is very strange reasoning, I need to revisit the algorithm)
            rest = []
        else:
            # Gather the rest of instruction after the branch joins ...
            rest = self.get_rest(inst)
            if not include_current_inst:
                # remove the current instruction (if-else/switch-case) from the list
                rest = rest[1:]

        for pid, tmp_path in tmp.failure_paths.items():
            path = tmp_path + rest
            self.failure_paths[pid] = path
        return

    def _handle_call(self, inst, more):
        debug(f'processing call {inst.name}', tag=MODULE_TAG)
        ctx = more.ctx
        func = inst.get_function_def()
        if func is None or func.is_empty():
            return
        b = func.body
        tmp = FindFailurePaths.do(b, self.info, func=func)
        if len(tmp.failure_paths) == 0:
            return
        if self.current_function is not None:
            # debug('function failure paths:', func.name, func.path_ids, tag=MODULE_TAG)
            self.current_function.path_ids.update(func.path_ids)
        self.new_declarations.extend(tmp.new_declarations)
        for path_id, internal_path in tmp.failure_paths.items():
            # Define a new function and,
            t = _get_fail_path_func_counter(path_id)
            tmp_name = f'__f{path_id}_{t}'
            new_func = Function(tmp_name, None)
            new_func.args = list(func.args)
            new_func.return_type = func.return_type
            new_func.body.extend_inst(internal_path)
            new_func.based_on = func
            sym_tbl = self.info.sym_tbl
            gs = sym_tbl.global_scope
            with sym_tbl.with_scope(gs):
                new_func.update_symbol_table(sym_tbl)

            self.new_declarations.append(new_func)

            # create a call instruction for it
            call_inst = clone_pass(inst)
            call_inst.name = tmp_name

            # NOTE: what if call instruction is part of another instruction
            # like assignment?
            prnt = self.parent_inst
            if prnt is None or ctx == BODY:
                first_inst = call_inst

                target = inst
            elif prnt.kind == clang.CursorKind.BINARY_OPERATOR:
                assert prnt.op == '=', 'I think it call instruction should be part of an assignment or a block of code'
                tmp_clone_lhs = clone_pass(prnt.lhs.children[0])
                first_inst = BinOp.build(tmp_clone_lhs, '=', call_inst)

                target = prnt
            else:
                debug(prnt, tag=MODULE_TAG)
                raise Exception('Conflicting with assumptions: I think a simplified code should have function either in a body of code or in the right handside of an assignment')

            rest = self.get_rest(target)[1:]
            gathered = [first_inst, ] + rest
            self.failure_paths[path_id] = gathered
            # debug('For handling a function call that may fail:', path_id, gathered, tag=MODULE_TAG)

    def _handle_fallback_point(self, inst, more):
        failure_path_id = _get_fail_counter()
        if inst.path_id != 0:
            # NOTE: Ignore this issue for now TODO: I need to address this
            debug('we are trying to overwrite another failure id (there is collision)', tag=MODULE_TAG)
        # assert inst.path_id == 0, 'we are trying to overwrite another failure id (there is collision)'
        assert failure_path_id not in _for_debuging_assigned_failure_numbers, 'We are assigning the same failure id to two different fallback points'
        _for_debuging_assigned_failure_numbers.add(failure_path_id)

        self.terminate = True
        self.skip_children()
        rest = self.get_rest(inst)
        self.failure_paths[failure_path_id] = rest
        inst.path_id = failure_path_id
        if self.current_function is not None:
            # debug('xxxx', self.current_function.name, failure_path_id, tag=MODULE_TAG)
            self.current_function.path_ids.add(failure_path_id)
        # debug(f'encounter a to-user instruction ({failure_path_id})',
        #         tag=MODULE_TAG)
        # debug(f'failure is aligned to:', inst.original)
        # debug('instructions for handling it:\n', rest, tag=MODULE_TAG)

    def process_current_inst(self, inst, more):
        # n = '[[main]]' if self.current_function is None else self.current_function.name
        # debug(n)
        if self.terminate:
            self.skip_children()
            return inst

        # TODO: if in a branch all possible paths fail, terminate the search

        match inst.kind:
            case instruction.TO_USERSPACE_INST:
                self._handle_fallback_point(inst, more)
            case clang.CursorKind.IF_STMT:
                self.skip_children()
                branches = (b for b in (inst.body, inst.other_body)
                        if b.has_children())
                include_target_inst = inst.is_modified()
                for b in branches:
                    self._handle_branch(inst, b, include_target_inst)
            case clang.CursorKind.SWITCH_STMT:
                self.skip_children()
                # NOTE: Expect the children to be CaseSTMT objects
                branches = (b for b in inst.body.children if b.has_children())
                include_target_inst = inst.is_modified()
                for b in branches:
                    self._handle_branch(inst, b, include_target_inst)
            case clang.CursorKind.DO_STMT | clang.CursorKind.WHILE_STMT:
                self.skip_children()
                branches = (b for b in (inst.body, inst.other_body)
                        if b.has_children())
                for b in branches:
                    self._handle_branch(inst, b, True)
            case clang.CursorKind.FOR_STMT:
                self.skip_children()
                if inst.body.has_children():
                    self._handle_branch(inst, inst.body, True)
            case clang.CursorKind.CALL_EXPR:
                self._handle_call(inst, more)
        return inst


def create_failure_paths(inst, info, more):
    """
    Find possible failure paths due to unsupported instructions
    """

    # TODO: Remove all the global state from all the modules includeing this
    global __fail_counter
    _for_debuging_assigned_failure_numbers.clear()
    __failure_path_func_book.clear()
    __fail_counter = 0

    obj = FindFailurePaths.do(inst, info, more)
    info.failure_paths = obj.failure_paths
    info.failure_path_new_funcs = obj.new_declarations
    info.user_prog.fallback_funcs_def = list(obj.new_declarations)
