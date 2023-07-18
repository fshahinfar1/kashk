import clang.cindex as clang


# TODO: How to make sure that `read` is the read system-call and not a simple
# function?
READ_PACKET = ['async_read_some', 'read']
WRITE_PACKET = ['async_write', 'async_write_some', 'write']

# TODO: is it formally correct to ignore a function? We should ignore a
# function based on the effects that it makes. If the effects are not of
# interest only then we can ignore a funciton.
IGNORE_FUNC = ['printf',]


def __is_ignored_function(cursor):
    if cursor.kind == clang.CursorKind.CALL_EXPR:
        if cursor.spelling in IGNORE_FUNC:
            return True
    return False


def get_namespace_of_cursor(cursor):
    cursor = cursor.type.get_declaration()
    namespace_name = ""
    parent_cursor = cursor.semantic_parent
    while parent_cursor is not None:
        # print(parent_cursor.spelling, parent_cursor.kind, parent_cursor.type.kind)
        if parent_cursor.kind == clang.CursorKind.NAMESPACE:
            namespace_name = parent_cursor.spelling
            # Continue looking for the top most namespace
        parent_cursor = parent_cursor.semantic_parent
    return namespace_name


def should_process_this_cursor(cursor):
    f = cursor.location.file
    if not f or not should_process_this_file(f.name):
        return False
    ns = get_namespace_of_cursor(cursor)
    if ns == 'asio':
        return False
    if __is_ignored_function(cursor):
        return False
    return True


def should_process_this_file(path):
    """
    Try to prune the search space by ignoring some library files.
    """
    ignore_headers = ['include/asio/', 'lib/gcc', 'usr/include/']
    for header in ignore_headers:
        if header in path:
            # error(f'ignore {path}')
            return False
    return True
