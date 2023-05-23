from sys import stderr


def error(*args):
    print('\033[31m', *args, '\033[0m', file=stderr)


def debug(*args):
    print('\033[33m', *args, '\033[0m', file=stderr)
