from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from prune import READ_PACKET, WRITE_PACKET, KNOWN_FUNCS
from data_structure import *
from instruction import *

from code_gen import gen_code
from passes.pass_obj import PassObject
from passes.clone import clone_pass

from passes.bpf_passes.mark_user_boundary import mark_user_boundary_pass


MODULE_TAG = '[Feasibility Pass]'
FAILED = 999
PARENT_INST = 1000

current_function = None
cb_ref = None
fail_ref = None
_has_processed = set()

_failed_val = None
_skip_inst = False
def set_skip(val):
    global _skip_inst
    global _failed_val
    if val:
        # remember what was the value of fail before going inside the block
        _failed_val = fail_ref.get(FAILED)
    else:
        # restore the failed value before going out of the block
        fail_ref.set(FAILED, _failed_val)
        # debug('Restore to', _failed_val)
        _failed_val = None
    _skip_inst = val


def get_skip():
    return _skip_inst


@contextmanager
def remember_func(func):
    global current_function
    tmp = current_function
    current_function = func
    try:
        yield None
    finally:
        current_function = tmp


def is_function_call_feasible(inst, info):
    func = inst.get_function_def()
    if func is None:
        current_func_name =  current_function.name if current_function is not None else '<unknown func>'
        error(f'Do not have function struct for {inst.name}', 'Invoked from', current_func_name)
        return False
    if func.is_empty():
        if func.name in (KNOWN_FUNCS + READ_PACKET + WRITE_PACKET):
            # It is fine
            func.may_fail    = False
            func.may_succeed = True
            return True
        # debug('does not know func:', func.name)
        func.may_fail    = True
        func.may_succeed = False
        return False

    processed_before = func.may_fail or func.may_succeed
    if processed_before:
        return func.may_succeed

    if func.get_name() not in _has_processed:
        # Let's protected against self loop
        _has_processed.add(func.get_name())
        with remember_func(func):
            with info.sym_tbl.with_func_scope(func.name):
                with cb_ref.new_ref(PARENT_INST, None):
                    body = _do_pass(func.body, info, PassObject())
                    assert body is not None, 'this pass should not remove anything'
                    func.body = body
    return True


def _check_annotation(inst, info, more):
    """
    Check and skip the Annotation that create their own blocks (e.g, CACHE).
    What is inside the ANNOTATED block may be infeasible but the annotations
    ask for a different implementation which fits BPF.

    But note that if the inner block fail, the function should have may_fail
    flag set.
    """
    if inst.kind != ANNOTATION_INST:
        return

    if inst.ann_kind in (Annotation.ANN_CACHE_BEGIN,
            Annotation.ANN_CACHE_BEGIN_UPDATE):
        # TODO: use the new Pass framework and add the skip option to it
        # NOTE: skip until end of the block
        set_skip(True)
    elif inst.ann_kind in (Annotation.ANN_CACHE_END,
            Annotation.ANN_CACHE_END_UPDATE):
        # NOTE: stop skiping instructions
        set_skip(False)


def _process_current_inst(inst, info, more):
    if inst.kind == clang.CursorKind.CALL_EXPR:
        if not is_function_call_feasible(inst, info):
            return inst, True
        func = inst.get_function_def()
        if func and current_function and func.may_fail:
            # The called function may fail so the current function may also fail
            current_function.may_fail = True
        # Although the function may fail or not the fact that current function
        # fails depend on whether the function may succeed.
        return inst, not func.may_succeed
    elif inst.kind == ANNOTATION_INST and inst.ann_kind == Annotation.ANN_SKIP:
        return inst, True
    return inst, False


def _process_child(child, inst, info, more):
    lvl, tag, parent_list = more.unpack()
    new_child = None
    if isinstance(child, list):
        new_child = []
        obj = more.repack(lvl + 1, tag, new_child)
        for i in child:
            new_inst = _process_child(i, inst, info, obj)
            if new_inst is None:
                if inst.kind == BLOCK_OF_CODE and inst.tag == BODY:
                    # It is a block of code, we do not want to remove the whole
                    # block just stop here.
                    break
                else:
                    # The argument, condition or ... of this instruction was
                    # not possible. Also remove the whole instruction.
                    return None
            new_child.append(new_inst)
    else:
        obj = more.repack(lvl + 1, tag, parent_list)
        new_child = _do_pass(child, info, obj)

    return new_child


def _do_pass(inst, info, more):
    """
    Description of how feasibility analysis is performed:
        The body of each function is analysed, until we reach to a end of the
        function. End of each function is marked with a `return' instruction.
        If a void function does not have a return instruction we must have add
        it in linear pass (before this pass).
        Reaching a return instruction means the function may terminate successfully.

        When a function invocation is found which might fail (meaning its
        implementation is not known (completely unfeasible to offload to BPF)
        or it calls a function that may fail) the current function is marked as
        possible to fail.)

        This information is used later to add ToUserspace (BPF-Userspace
        boundaries) instruction where needed to fallback to userspace.
    """
    lvl, ctx, parent_list = more.unpack()
    new_children = []
    failed = fail_ref.get(FAILED)
    if (current_function and not failed and
            inst.kind == clang.CursorKind.RETURN_STMT):
        current_function.may_succeed = True

    _check_annotation(inst, info, more)
    if failed or inst.ignore is True:
        return clone_pass(inst, info, PassObject())

    with cb_ref.new_ref(ctx, parent_list):
        inst, failed = _process_current_inst(inst, info, more)
        assert inst is not None
        if failed:
            if current_function:
                current_function.may_fail = True
                text, _ = gen_code([inst,], info)
                debug(f'Failed @{current_function.name} on:', text, inst,
                        tag=MODULE_TAG)
            # Not a stack
            fail_ref.set(FAILED, True)
        # Continue deeper
        for child, tag in inst.get_children_context_marked():
            with fail_ref.new_ref(FAILED, failed):
                obj = PassObject.pack(lvl + 1, tag, parent_list)
                parent = inst if inst.kind != BLOCK_OF_CODE else cb_ref.get(PARENT_INST)
                with cb_ref.new_ref(PARENT_INST, parent):
                    new_child = _process_child(child, inst, info, obj)
                if new_child is None:
                    return None
                failed = fail_ref.get(FAILED)
            # Propagate failure to upper level
            # We are not propagating when we are branching to a different path.
            parent = cb_ref.get(PARENT_INST)
            if parent is None or parent.kind not in BRANCHING_INSTRUCTIONS:
                fail_ref.set(FAILED, failed)
            new_children.append(new_child)
    new_inst = inst.clone(new_children)
    return new_inst


def _do_feasibility_analisys(inst, info, more):
    global cb_ref
    global fail_ref
    cb_ref = CodeBlockRef()
    fail_ref = CodeBlockRef()

    func = more.get('func', None)
    with remember_func(func):
        with cb_ref.new_ref(PARENT_INST, None):
            with fail_ref.new_ref(FAILED, False):
                return _do_pass(inst, info, more)


def feasibilty_analysis_pass(inst, info, more):
    """
    Start the analysis from the given function and perform it on the all know
    functions.
    """
    res = _do_feasibility_analisys(inst, info, more)
    for func in Function.directory.values():
        if func.may_succeed or func.may_fail:
            continue
        if func.is_empty():
            # debug(func.name, 'does not have implementation')
            if func.name in KNOWN_FUNCS:
                func.may_fail = False
                func.may_succeed = True
            else:
                func.may_fail = True
                func.may_succeed = False
            continue
        if not func.is_used_in_bpf_code:
            # It is not used why do I care?
            continue
        obj = PassObject()
        obj.func = func
        _do_feasibility_analisys(func.body, info, obj)
        assert func.may_fail or func.may_succeed, f'After this processing we should have decide if function can fail or not (func: {func.name})'

    res = mark_user_boundary_pass(res, info, PassObject())
    return res
