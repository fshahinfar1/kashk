from sys import stderr, stdout

"""
Color Table (16 bit)
 	Normal 	Bright
Black 	0 	8
Red 	1 	9
Green 	2 	10
Yellow 	3 	11
Blue 	4 	12
Purple 	5 	13
Cyan 	6 	14
White 	7 	15
"""

g_counter = 0
g_last_line = ''

def is_repeating(args, kwargs):
    global g_counter
    global g_last_line
    sep = ' ' if 'sep' not in kwargs else kwargs['sep']
    new_line = sep.join(map(str, args))
    # print(new_line, '||', g_last_line)
    if new_line == g_last_line:
        g_counter += 1
        return True
    else:
        g_last_line = new_line
    return False


def clear_repeating():
    global g_counter
    global g_last_line
    if g_counter > 0:
        print('\n')
        g_last_line = ''
    g_counter = 0

def error(*args, **kwargs):
    if is_repeating(args, kwargs):
        print(f'\r(x{g_counter}) ', end='', sep='', file=stderr)
    else:
        clear_repeating()
        print('\033[31m', *args, '\033[0m', file=stderr, **kwargs)


def debug(*args, **kwargs):
    clear_repeating()
    print('\033[33m', *args, '\033[0m', file=stdout, **kwargs)

def report(*args, **kwargs):
    clear_repeating()
    print('\033[36m', *args, '\033[0m', file=stdout, **kwargs)
