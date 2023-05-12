import sys
import clang.cindex as clang

from utility import parse_file, find_elem, get_code
from understand_program_state import extract_state
from bpf import SK_SKB_PROG


def generate_offload(file_path, entry_func):
    # This is the BPF program object we want to build
    prog = SK_SKB_PROG()

    cursor = parse_file(file_path)

    # for c in cursor.get_children():
    #     if 'Server' in c.spelling:
    #         for c2 in c.get_children():
    #             print(c2.spelling, c2.kind)

    # Get the state needed for handling the request
    states, decls = extract_state(cursor)

    # Check if there is any type declaration that we need (enum or struct)
    # for s in states:
    #     # print(s.kind, s)
    #     if s.kind == clang.TypeKind.ELABORATED:
    #         c = s.cursor.type.get_declaration()
    #         decl = get_code(c) + ';'
    #         prog.add_decleration(decl)

    for s in states:
        prog.add_connection_state(s)
    for d in decls:
        prog.add_decleration(d)

    # Print the code we have generated
    print(prog.get_code())


def process_entry_function(cursor, entry_func):
    func = find_elem(cursor, entry_func)
    if func is None:
        print('Did not found the entry function', file=sys.stderr)
        return


    text = get_code(func)
    print(text)
