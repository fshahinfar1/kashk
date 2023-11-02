import clang.cindex as clang

from instruction import *
from dfs import DFSPass


top_block_stack = []
EV_LOOP = 1
SWITCH = 2
LOOP = 3


def _return_drop_inst(info):
    val      = Literal(info.prog.get_drop(), clang.CursorKind.INTEGER_LITERAL)
    ret_inst = Return.build([val,])
    return ret_inst


def _do_pass(inst, info, more):
    new_children = []

    need_pop = False
    if inst.kind == clang.CursorKind.RETURN_STMT:
        # Returing from the event loop
        return _return_drop_inst(info)
    elif inst.kind == clang.CursorKind.CONTINUE_STMT:
        top_index = len(top_block_stack)
        while top_block_stack[top_index] == SWITCH:
            # continue is ignored in switch statements
            top_index -= 1
        if top_block_stack[top_index] == EV_LOOP:
            return _return_drop_inst(info)
    elif inst.kind == clang.CursorKind.BREAK_STMT:
        if top_block_stack[-1] == EV_LOOP:
            return _return_drop_inst(info)
    elif inst.kind == clang.CursorKind.SWITCH_STMT:
        top_block_stack.append(SWITCH)
        need_pop = True
    elif (inst.kind == clang.CursorKind.FOR_STMT
            or inst.kind == clang.CursorKind.DO_STMT
            or inst.kind == clang.CursorKind.WHILE_STMT):
        top_block_stack.append(LOOP)
        need_pop = True

    # Continue deeper
    for child, tag in inst.get_children_context_marked():
        is_list = isinstance(child, list)
        if not is_list:
            child = [child,]

        new_child = []
        for i in child:
            new_inst = _do_pass(i, info, None)
            if new_inst is None:
                if not is_list:
                    return None
                else:
                    continue
            new_child.append(new_inst)

        if not is_list:
            new_child = new_child[0]
        new_children.append(new_child)


    if need_pop:
        top_block_stack.pop()

    new_inst = inst.clone(new_children)
    return new_inst


def _has_unterminated_path(inst, info):
    d = DFSPass(inst)
    for inst, lvl in d:
        if inst.kind == clang.CursorKind.RETURN_STMT:
            return False
        elif inst.kind == clang.CursorKind.CALL_EXPR:
            # Check if we are transmitting the packet
            if inst.wr_buf is not None:
                return False
        elif inst.kind == clang.CursorKind.IF_STMT:
            c1 = _has_unterminated_path(inst.body, info)
            c2 = _has_unterminated_path(inst.other_body, info)
            if c1 and c2:
                return False
        elif inst.kind == clang.CursorKind.SWITCH_STMT:
            for case in inst.body:
                c = _has_unterminated_path(case, info)
                if not c:
                    break
            else:
                # All of the cases termintated
                return False
        d.go_deep()
    return True


def loop_end_pass(inst, info, more):
    assert isinstance(inst, Block) and inst.tag == BODY
    top_block_stack.append(EV_LOOP)
    res = _do_pass(inst, info, more)

    if _has_unterminated_path(res, info):
        res.add_inst(_return_drop_inst(info))
    return res
