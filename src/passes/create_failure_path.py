import clang.cindex as clang
import instruction
from log import debug
from instruction import *
from data_structure import *
from passes.code_pass import Pass
from passes.clone import clone_pass
from helpers.instruction_helper import show_insts



MODULE_TAG = "[Create Failure Paths]"


__fail_counter = 0
def _get_fail_counter():
    global __fail_counter
    __fail_counter += 1
    return __fail_counter


class GatherRestInstruction(Pass):
    def __init__(self, info):
        super().__init__(info)
        self.found = False
        self.gathered = []
        self.target = None

    def process_current_inst(self, inst, more):
        if not self.found and inst == self.target:
            self.found = True

        if self.found:
            self.gathered.append(inst)
            self.skip_children()
        return inst


class FindFailurePaths(Pass):
    def __init__(self, info):
        super().__init__(info)
        self.failure_paths = {}
        self.new_declarations = []
        self.terminate = False
        self.first_inst = None

    def get_rest(self, inst):
        """
        Get the rest of the instruction in this block
        @param inst: current instruction
        """
        tmp = GatherRestInstruction.do(self.first_inst, self.info,
                target=inst)
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
        tmp = FindFailurePaths.do(b, self.info, first_inst=b)
        if len(tmp.failure_paths) == 0:
            # did not failed
            return False
        self.new_declarations.extend(tmp.new_declarations)
        rest = self.get_rest(inst)
        if not include_current_inst:
            # remove the current instruction (if-else/switch-case) from the list
            rest = rest[1:]
        for pid, tmp_path in tmp.failure_paths.items():
            path = tmp_path + rest
            self.failure_paths[pid] = path
        return True

        # self.terminate = True

    def _handle_call(self, inst, more):
        # debug(f'processing call {inst.name}', tag=MODULE_TAG)
        ctx = more.ctx
        func = inst.get_function_def()
        if func is None or func.is_empty():
            return
        b = func.body
        tmp = FindFailurePaths.do(b, self.info, func=func, first_inst=b)
        if len(tmp.failure_paths) == 0:
            return
        self.new_declarations.extend(tmp.new_declarations)
        for path_id, internal_path in tmp.failure_paths.items():
            # Define a new function and,
            tmp_name = f'__f{path_id}'
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

        # self.terminate = True

    def process_current_inst(self, inst, more):
        if self.terminate:
            self.skip_children()
            return inst

        # TODO: if in a branch all possible paths fail, terminate the search

        match inst.kind:
            case instruction.TO_USERSPACE_INST:
                failure_path_id = _get_fail_counter()
                assert isinstance(failure_path_id, int)
                self.terminate = True
                rest = self.get_rest(inst)[1:]
                self.failure_paths[failure_path_id] = rest
                # debug(f'encounter a to-user instruction ({failure_path_id})',
                #         tag=MODULE_TAG)
                # debug('instructions for handling it:\n', rest, tag=MODULE_TAG)
            case clang.CursorKind.IF_STMT:
                self.skip_children()
                branches = (b for b in (inst.body, inst.other_body)
                        if b.has_children())
                for b in branches:
                    self._handle_branch(inst, b, False)
            case clang.CursorKind.SWITCH_STMT:
                self.skip_children()
                # NOTE: Expect the children to be CaseSTMT objects
                branches = (b for b in inst.body.children if b.has_children())
                for b in branches:
                    self._handle_branch(inst, b, False)
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
    obj = FindFailurePaths.do(inst, info, more, first_inst=inst)
    info.failure_paths = obj.failure_paths
    info.failure_path_new_funcs = obj.new_declarations
    info.user_prog.fallback_funcs_def = list(obj.new_declarations)
