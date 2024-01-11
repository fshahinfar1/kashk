from contextlib import contextmanager
from log import debug
from instruction import *
from data_structure import *
from prune import MEMORY_ACCESS_FUNC

from passes.pass_obj import PassObject
from passes.mark_relevant_code import mark_relevant_code
from passes.clone import clone_pass


MODULE_TAG = '[Replace Func Ptr]'
exclude_inst_flag = False
func_ptr_mapping = {}
cb_ref = CodeBlockRef()
parent_stack = []
loop_ann = None
skip_target = None

def _set_skip_target(t):
    global skip_target
    skip_target = t


@contextmanager
def set_parent(p):
    try:
        parent_stack.append(p)
        yield p
    finally:
        parent_stack.pop()


def find_first_parent_of_kind(inst_kind, tag):
    for p in reversed(parent_stack):
        if p.kind == inst_kind:
            if tag is not None and p.tag == tag:
                return p
    return None


def find_annotation_end_block(ann_inst, parent_children):
    # Gather instructions between BEGIN & END
    begin = False
    insts = []
    found_end_annotation = False
    target = None
    for child in parent_children:
        if child == ann_inst:
            begin = True
            continue
        if (child.kind == ANNOTATION_INST and
                child.ann_kind == ann_inst.end_block_ann_kind()):
            target = child
            found_end_annotation = True
            # debug('*** Stop gathering')
            break
        if not begin:
            # continue until finding the begining of the block
            continue
        insts.append(child)
    err = 'The end of annotation block must be specified'
    assert found_end_annotation and target is not None, err
    return insts, target


def _set_exclude_flag(val):
    global exclude_inst_flag
    exclude_inst_flag = val


def _set_loop_ann(val):
    global loop_ann
    loop_ann = val


def _process_annotation(inst, info):
    if inst.ann_kind == Annotation.ANN_FUNC_PTR:
        ptr, actual = inst.msg.split(Annotation.FUNC_PTR_DELIMITER)
        func_ptr_mapping[ptr] = actual
        # debug(MODULE_TAG, ptr, '-->', actual)
        return None
    elif inst.ann_kind == Annotation.ANN_EXCLUDE_BEGIN:
        _set_exclude_flag(True)
        return None
    elif inst.ann_kind == Annotation.ANN_EXCLUDE_END:
        _set_exclude_flag(False)
        return None
    elif inst.ann_kind == Annotation.ANN_LOOP:
        repeat = int(inst.msg)
        _set_loop_ann(repeat)
        return None

    if inst.is_block_annotation():
        parent = find_first_parent_of_kind(BLOCK_OF_CODE, BODY)
        assert parent is not None, 'Failed to find the top block of code?!'
        parent_children = parent.get_children()
        tmp_insts, until = find_annotation_end_block(inst, parent_children)
        new_inst = clone_pass(inst)
        new_inst.block.extend_inst(tmp_insts)
        _set_skip_target(until)
        debug('skip target is:', until, tag=MODULE_TAG)
        blk = cb_ref.get(BODY)
        blk.append(new_inst)
        return new_inst

    # Do not remove the rest of annotations
    return inst


def _process_current_inst(inst, info):
    if loop_ann is not None:
        # Apply the loop annotation
        if inst.kind in MAY_HAVE_BACKWARD_JUMP_INSTRUCTIONS:
            inst.repeat = loop_ann
        elif (inst.kind == clang.CursorKind.CALL_EXPR and
                inst.name in MEMORY_ACCESS_FUNC):
            inst.repeat = loop_ann
        else:
            raise Exception('The Loop annotation is not set to a correct instruction')
        _set_loop_ann(None)
        return inst

    if inst.kind == ANNOTATION_INST:
        return _process_annotation(inst, info)
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        if inst.is_func_ptr:
            actual = func_ptr_mapping.get(inst.name)
            if actual is not None:
                # bind function pointer to an actual function
                report(f'Function {inst.name} is replaced with {actual}', tag=MODULE_TAG)
                new_inst = clone_pass(inst, info, PassObject())
                new_inst.name = actual
                new_inst.is_func_ptr = False

                func = new_inst.get_function_def()
                assert func is not None, f'Function {new_inst.name} was not found'
                if not func.is_used_in_bpf_code:
                    # This function has just got accessibile
                    assert func is not None
                    func.is_used_in_bpf_code = True
                    info.prog.declarations.insert(0, func)

                    # NOTE: I am not putting this pass before
                    # mark_relevant_code pass because I do not want to analyse
                    # all the functions.
                    mark_relevant_code(func.body, info, None)
                return new_inst
    return inst


def _do_pass(inst, info):
    inst = _process_current_inst(inst, info)
    if inst is None:
        return inst
    new_children = []
    with set_parent(inst):
        for child, tag in inst.get_children_context_marked():
            if isinstance(child, list):
                new_child = []
                with cb_ref.new_ref(tag, new_child):
                    for i in child:
                        new_inst = _do_pass(i, info)
                        if skip_target is not None:
                            # TODO: This skipping is a hack won't work well
                            if i == skip_target:
                                _set_skip_target(None)
                                debug('found skip target', i, tag=MODULE_TAG)
                            else:
                                continue

                        if exclude_inst_flag:
                            continue

                        if new_inst is not None:
                            new_child.append(new_inst)
            else:
                new_child = _do_pass(child, info)
            new_children.append(new_child)
    new_inst = inst.clone(new_children)
    return new_inst


def primary_annotation_pass(bpf, info, more):
    """
    Apply some of the annotations
    1. Function pointer
    2. Exclude regions
    3. Loops, Memcpy, ... bounds
    4. Rearange instruction to be childern of block annotations
    """
    global func_ptr_mapping, parent_stack, cb_ref
    func_ptr_mapping = {}
    res = _do_pass(bpf, info)
    for func in Function.directory.values():
        if func.is_used_in_bpf_code:
            parent_stack = []
            cb_ref = CodeBlockRef()
            func.body = _do_pass(func.body, info)
    return res
