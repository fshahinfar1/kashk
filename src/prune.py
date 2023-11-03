import clang.cindex as clang
from utility import report_on_cursor
from log import debug, error, report
from instruction import UnaryOp


# TODO: How to make sure that `read` is the read system-call and not a simple
# function?
READ_PACKET = ('async_read_some', 'recv', 'read', 'recvfrom', 'recvmsg')
WRITE_PACKET = ('async_write', 'async_write_some', 'write', 'send', 'sendto', 'sendmsg')
COROUTINE_FUNC_NAME = ('await_resume', 'await_transform', 'await_ready', 'await_suspend')

# TODO: is it formally correct to ignore a function? We should ignore a
# function based on the effects that it makes. If the effects are not of
# interest only then we can ignore a funciton.
IGNORE_FUNC = ('printf', 'fprintf')

KNOWN_FUNCS = ('malloc', 'memcpy', 'memmove', 'memset', 'strcpy', 'strncpy',
                'strlen', 'strcmp', 'ntohs', 'ntohl', 'ntohll', 'htons',
                'htonl', 'htonll')

OUR_IMPLEMENTED_FUNC = ('bpf_memcpy', 'bpf_strncpy', 'bpf_ntohs', 'bpf_ntohl',
                        'bpf_htons', 'bpf_htonl', 'bpf_cpu_to_be64',
                        'bpf_be64_to_cpu')


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
    elif cursor.kind == clang.CursorKind.UNARY_OPERATOR:
        tokens = [t.spelling for t in cursor.get_tokens()]
        count_token = len(tokens)
        if count_token < 2:
            error('Unary operator with less than 2 tokens will fail to convert to UnaryOp object. It was ignored!', cursor, tokens)
            return True
        # Basically check if we can find the unary operator
        candid = tokens[0]
        if candid not in UnaryOp.OPS:
            for candid in tokens:
                if candid in UnaryOp.OPS:
                    break
            else:
                return True
    elif cursor.kind in (clang.CursorKind.BINARY_OPERATOR, clang.CursorKind.COMPOUND_ASSIGNMENT_OPERATOR):
        children = list(cursor.get_children())
        tokens = list(cursor.get_tokens())
        count_token = len(tokens)
        if count_token == 0:
            return True

        # Basically check if we can find the binary operator
        lhs = next(cursor.get_children())
        lhs_tokens = len(list(lhs.get_tokens()))
        # First token after lhs
        tokens = len(list(cursor.get_tokens()))
        if lhs_tokens >= tokens:
            # error('Binary operator which we can not find the operator for')
            return True

    return False
