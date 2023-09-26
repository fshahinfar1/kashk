from sys import stderr

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

def error(*args, **kwargs):
    print('\033[31m', *args, '\033[0m', file=stderr, **kwargs)


def debug(*args, **kwargs):
    print('\033[33m', *args, '\033[0m', file=stderr, **kwargs)

def report(*args, **kwargs):
    print('\033[36m', *args, '\033[0m', file=stderr, **kwargs)
