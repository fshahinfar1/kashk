import clang.cindex as clang


class CaseBlock:
    def __init__(self):
        self.cond_cursor = None
        self.cursor = None
        self.body_cursors = []
        self.kind = None

    def has_data(self):
        return self.cond_cursor is not None or len(self.body_cursors) > 0


def parse_switch_case(c, info):
    """
    @returns cursor to the switch statement condition, list of case blocks
    """
    children = c.get_children()
    sw_cond = next(children)
    main_body = next(children)

    # Group instructions for each case
    main_body = list(main_body.get_children())
    assert main_body[0].kind in (clang.CursorKind.CASE_STMT, clang.CursorKind.DEFAULT_STMT)
    cases =  []
    cur = CaseBlock()
    for cursor in main_body:
        if cursor.kind in (clang.CursorKind.CASE_STMT, clang.CursorKind.DEFAULT_STMT):
            if cur.has_data():
                cases.append(cur)
            cur = CaseBlock()
            cur.kind = cursor.kind
            cur.cursor = cursor
            children = list(cursor.get_children())
            assert len(children) == 2 or len(children) == 1
            if len(children) == 2:
                # Case:
                cur.cond_cursor = children[0]
                body_cursor = children[1]
            else:
                # Default:
                cur.cond_cursor = None
                body_cursor = children[0]

            while body_cursor.kind in (clang.CursorKind.CASE_STMT, clang.CursorKind.DEFAULT_STMT):
                # NOTE: trying to fix the case when a case does not have a body
                if cur.has_data():
                    cases.append(cur)
                cur = CaseBlock()
                cur.kind = body_cursor.kind
                cur.cursor = body_cursor
                children = list(body_cursor.get_children())
                assert len(children) == 2 or len(children) == 1
                if len(children) == 2:
                    cur.cond_cursor = children[0]
                    body_cursor = children[1]
                else:
                    cur.cond_cursor = None
                    body_cursor = children[0]
            cur.body_cursors.append(body_cursor)
        else:
            cur.body_cursors.append(cursor)
    if cur.has_data():
        cases.append(cur)
    return sw_cond, cases
