from sys import stderr

def error(*args):
    print(*args, file=stderr)

def debug(*args):
    print(*args, file=stderr)
