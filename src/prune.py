import clang.cindex as clang
from utility import report_on_cursor
from log import debug, error, report


# TODO: How to make sure that `read` is the read system-call and not a simple
# function?
READ_PACKET = ['async_read_some', 'read', 'recvfrom']
WRITE_PACKET = ['async_write', 'async_write_some', 'write']
COROUTINE_FUNC_NAME = ('await_resume', 'await_transform', 'await_ready', 'await_suspend')

# TODO: is it formally correct to ignore a function? We should ignore a
# function based on the effects that it makes. If the effects are not of
# interest only then we can ignore a funciton.
IGNORE_FUNC = ['printf', 'fprintf']

KNOWN_FUNCS = ['memcpy', 'memmove', 'strcpy', 'strncpy', 'strlen', 'strcmp']


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


def should_ignore_cursor(cursor):
    """
    The difference with `should_process_this_cursor' is,
    this function is used to decide if the cursor should be removed from all processing.
    The mentioned function decides if the cursor belongs to user-space program.
    """
    if __is_ignored_function(cursor):
        return True
    if cursor.kind == clang.CursorKind.UNARY_OPERATOR:
        count_token = len(list(cursor.get_tokens()))
        if count_token < 2:
            error('Unary operator with less than 2 tokens will fail to convert to UnaryOp object. It was ignored!')
            return True
    if cursor.kind == clang.CursorKind.BINARY_OPERATOR:
        count_token = len(list(cursor.get_tokens()))
        # report_on_cursor(cursor)
        # children = list(cursor.get_children())
        # report_on_cursor(children[0])
        # x = list(children[0].get_children())
        # while x:
        #     report_on_cursor(x[0])
        #     x = list(x[0].get_children())
        # print(count_token)
        if count_token == 0:
            error('Binary operator with zero tokens, this will fail to convert to BinOp so it was ignored!')
            # report_on_cursor(cursor)
            # This was observed to be a assert statement, errno == ..., what other statement does it include?
            return True
