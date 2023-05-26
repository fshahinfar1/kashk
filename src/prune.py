READ_PACKET = 'async_read_some'
WRITE_PACKET = 'async_write'


def should_process_this_cursor(cursor):
    f = cursor.location.file
    return f and should_process_this_file(f.name)


def should_process_this_file(path):
    """
    Try to prune the search space by ignoring some library files.
    """
    ignore_headers = ['include/asio/', 'lib/gcc',]
    for header in ignore_headers:
        if header in path:
            # error(f'ignore {path}')
            return False
    return True
