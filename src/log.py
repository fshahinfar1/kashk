from sys import stderr, stdout

"""
Color Table (16 bit)
	Normal	Bright
Black	0	8
Red 	1	9
Green	2	10
Yellow	3	11
Blue	4	12
Purple	5	13
Cyan	6	14
White	7	15
"""

DEBUG  = 0
ERROR  = 1
REPORT = 2

g_counter = 0
g_last_line = (None, '')
g_filter = None


colors = {
        DEBUG:  '\033[33m',
        ERROR:  '\033[31m',
        REPORT: '\033[36m'
        }

output_file = {
        DEBUG:  stdout,
        ERROR:  stderr,
        REPORT: stdout,
        }


def is_repeating(kind, args, kwargs):
    global g_counter
    global g_last_line
    sep = ' ' if 'sep' not in kwargs else kwargs['sep']
    new_line = sep.join(map(str, args))
    # print(new_line, '||', g_last_line)
    if kind == g_last_line[0] and new_line == g_last_line[1]:
        g_counter += 1
        return True
    else:
        g_last_line = kind, new_line
    return False


def clear_repeating():
    global g_counter
    global g_last_line
    if g_counter > 1:
        print('\n')
        g_last_line = None, ''
    g_counter = 1


def filter_log(*args):
    global g_filter
    g_filter = set(args)


def core_print_fn(mode, *args, **kwargs):
    tag = kwargs.get('tag')
    if 'tag' in kwargs:
        del kwargs['tag']
    if g_filter is not None and tag not in g_filter:
        return

    clr = colors[mode]
    out = output_file[mode]
    if is_repeating(mode, args, kwargs):
        print(f'\r(x{g_counter}) ', end='', sep='', file=stdout)
    else:
        clear_repeating()
        print(clr, tag, *args, '\033[0m', file=stdout, **kwargs)


def error(*args, **kwargs):
    core_print_fn(ERROR, *args, **kwargs)


def debug(*args, **kwargs):
    core_print_fn(DEBUG, *args, **kwargs)


def report(*args, **kwargs):
    core_print_fn(REPORT, *args, **kwargs)
