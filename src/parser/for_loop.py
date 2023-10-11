"""
This file is a work around (just a hack) for the Libclang limitation when
parsing For loops.
"""
from utility import report_on_cursor, token_to_str
from log import *


def _matching_close_paren(string, begin, symbol='()'):
    """
    Find the index of matching close parenthesis
    """
    assert len(symbol) == 2
    begin_chr = symbol[0]
    end_chr = symbol[1]
    assert string[begin] == begin_chr
    B = 1
    E = 2
    stack = [B]
    off = begin + 1
    for i, c in enumerate(string[off:]):
        if c == begin_chr:
            stack.append(B)
        elif c == end_chr:
            stack.pop()
            if not stack:
                return i + off
    return -1


def _split_by(string, delim):
    """
    Split a string by given delimiter. Noting that the delimiter should not be
    a sorrunded with quotetions. 
    """
    split_points = []
    NORMAL = 1
    LITERAL = 2
    COMMENT = 3 # TODO: not considering this
    state = NORMAL

    l_match = []
    for i, c in enumerate(string):
        if state == NORMAL:
            if c == "'":
                l_match.append("'")
                state = LITERAL
            elif c == '"':
                l_match.append('"')
                state = LITERAL
            elif c == delim:
                split_points.append(i)
        elif state == LITERAL:
            if c == l_match[-1]:
                l_match.pop()
                state = NORMAL
    chips = []
    cur = 0
    for point in split_points:
        chips.append(string[cur:point])
        cur  = point + 1
    chips.append(string[cur:])
    return chips


def parse_for_loop_stmt(cursor):
    # For loop syntax: for(init, cond, post) body
    children = list(cursor.get_children())
    children.reverse()

    # I try to parse the For loop my self
    tokens = token_to_str(cursor.get_tokens())
    pbegin = tokens.index('(')
    pend   = _matching_close_paren(tokens, pbegin, '()')
    parenthesis = tokens[pbegin+1:pend]
    # actual_children = parenthesis.split(';')
    actual_children = _split_by(parenthesis, ';')

    # debug(tokens)
    # debug(actual_children)
    # debug(children)

    tmp_list = []
    # Init, Cond, Post
    for ptr in actual_children:
        if ptr:
            tmp_list.append(children.pop())
        else:
            tmp_list.append(None)
    # Body
    if children:
        tmp_list.append(children.pop())
    else:
        tmp_list.append(None)
    return tmp_list
