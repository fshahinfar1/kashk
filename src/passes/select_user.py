from contextlib import contextmanager
import clang.cindex as clang

from log import error, debug
from data_structure import *
from instruction import *

from bpf_code_gen import gen_code
from passes.pass_obj import PassObject


MODULE_TAG = '[Select Userspace Pass]'

# has_failed = False
# first_failing_block = False
# list_user_inst = []

# def end_userspaec_path(info):
#     """
#     This function is invoked when reaching end of a path which should be
#     processed in userspace.
#     """
#     global list_user_inst
#     # debug('list of instruction for a userspace path:\n', list_user_inst)
#     inst = Block(BODY)
#     inst.children = list_user_inst
#     info.user_prog.add_path(inst)
#     # Get ready for another path
#     list_user_inst = []


# # TODO: This function is important, complex, and I am not sure that I remember
# # how exactly it is working. Find a way to reduce the complexity.
# @contextmanager
# def remember_boundry(ctx, value, info, prev_ctx, prev_inst):
#     global has_failed
#     global first_failing_block

#     try:
#         tmp_failing_block = first_failing_block
#         if ctx == BODY:
#             # The failing state changes when switching between blocks
#             tmp = has_failed
#             has_failed = value
#         yield None
#     finally:
#         first_failing_block = tmp_failing_block
#         is_begining = (prev_ctx == BODY
#                 and has_failed
#                 and not first_failing_block)
#         if is_begining:
#             # The inst is the first instruction in the first_failing_block that
#             # fails (in the top block)
#             list_user_inst.append(prev_inst)
#             first_failing_block = True

#         if ctx == BODY:
#             had_failed = has_failed
#             has_failed = tmp

#             # Check if userspace path boundry finishes
#             if had_failed and not has_failed:
#                 # The program has not failed in this context but just before
#                 # switching to this context (in a child context) it had failed!
#                 # It shows end of a path which needs to be moved to userspace!
#                 end_userspaec_path(info)
#                 if current_function.may_fail and not current_function.may_succeed:
#                     has_failed = True


# def _do_pass(inst, info, more):
#     global has_failed

#     lvl, ctx, parent_list = more
#     new_children = []

#     # debug('T' if first_failing_block else 'F', '|' * lvl, '\'-->' , inst, '  context:', ctx)

#     with cb_ref.new_ref(ctx, parent_list):
#         if not has_failed:
#             # Process current instruction
#             inst, fails = _process_current_inst(inst, info, more)
#         else:
#             # Has failed, hence does not need processing

#             if first_failing_block:
#                 list_user_inst.append(inst)

#             # Remove this instruction from BPF program and do not investigate
#             # its children.
#             inst, fails = None, False

#         if inst is None:
#             # This instruction should be removed
#             return None

#         if fails and not has_failed:
#             # debug('>>>> It fails here <<<<')
#             has_failed = True
#             to_user_inst = ToUserspace.from_func_obj(current_function)
#             blk = cb_ref.get(BODY)
#             blk.append(to_user_inst)

#             # Mark the function as failed
#             if current_function:
#                 current_function.may_fail = True

#             # Remove this instruction.
#             return None

#         # Continue deeper
#         for child, tag in inst.get_children_context_marked():
#             # This function helps with knowing the boundry of BPF vs Userspace
#             # programs
#             with remember_boundry(tag, has_failed, info, ctx, inst):
#                 new_child = _process_child(child, inst, info, lvl, tag, parent_list)
#             if new_child is None:
#                 return None
#             new_children.append(new_child)

#             if inst.kind == clang.CursorKind.RETURN_STMT:
#                 current_function.may_succeed = True

#     new_inst = inst.clone(new_children)
#     return new_inst


def _clone(inst, info, more):
    lvl, ctx, parent_list = more.unpack()
    new_children = []

    # Continue deeper
    for child, tag in inst.get_children_context_marked():
        if isinstance(child, list):
            new_child = []
            for i in child:
                obj = PassObject.pack(lvl+1, tag, new_child)
                new_inst = _do_pass(i, info, obj)
                new_child.append(new_inst)
        else:
            obj = PassObject.pack(lvl+1, tag, parent_list)
            new_child = _do_pass(child, info, obj)
        new_children.append(new_child)

    new_inst = inst.clone(new_children)
    return new_inst


# TODO: the logic relies on the fact that ToUserspace instructions are found
# only inside BODY blocks
def _do_pass(inst, info, more):
    lvl = more.lvl
    ctx = more.ctx
    if not hasattr(more, 'in_user_land'):
        more.in_user_land = False
        more.remember = None


    if inst.kind != BLOCK_OF_CODE:
        debug(f'{lvl:3d}', ("|" * lvl) + '+->', inst, f'(signal:{more.in_user_land})')

    if inst.kind == TO_USERSPACE_INST:
        debug('reach "to user space inst"')
        more.in_user_land = True
        # remember is a list, and its reference would be shared to the children
        more.remember = []
        return
    elif inst.kind == clang.CursorKind.CALL_EXPR:
        func = inst.get_function_def()
        if func:
            # Step inside the function
            obj = PassObject()
            with info.sym_tbl.with_func_scope(inst.name):
                debug('Investigate:', inst.name)
                ret = _do_pass(func.body, info, obj)
                # TODO: should I propagate user land signal?
            debug (f'step out of function: {inst.name} and userland state in function is: {obj.in_user_land}')

            if func.may_fail:
                if not func.may_succeed:
                    debug('it is a failure for sure!')
                    more.in_user_land = True
                    more.remember = [] # a new list
                else:
                    # The function may succeed
                    pass
            return

    for child, tag in inst.get_children_context_marked():
        if not isinstance(child, list):
            child = [child]

        boundy_begin_flag = False
        for i in child:
            # Look deeper
            obj = more.repack(lvl+1, tag, None)
            ret = _do_pass(i, info, obj)

            prev_signal = more.in_user_land
            cur_signal =  obj.in_user_land

            # Propagate the userland signal
            more.in_user_land = obj.in_user_land
            more.remember = obj.remember

            if tag == BODY and cur_signal and not prev_signal:
                boundy_begin_flag = True
                assert more.in_user_land is True
                assert more.remember is not None
                debug('set flag')

            if more.in_user_land and boundy_begin_flag:
                debug(f'{lvl:3d}', ("|" * lvl * 1) + '+->', '(selected)', inst)
                if i.kind == TO_USERSPACE_INST:
                    # do not add this instruction to the list
                    continue
                more.remember.append(i)

        if boundy_begin_flag:
            # The userland boundy was found in this block. And this block
            # has ended.
            debug('---------------------------------')
            debug('## number of user inst:', len(more.remember))
            debug(more.remember)
            debug('---------------------------------')
            # Set it off! do not propagate
            more.in_user_land = False
            more.remember = None


def select_user_pass(inst, info, more):
    return _do_pass(inst, info, more)
