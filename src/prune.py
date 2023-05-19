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
