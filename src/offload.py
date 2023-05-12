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

    # Expect to store per connection state on this class
    states = extract_state(cursor)
    for s in states:
        prog.add_connection_state(s)

    # Print the code we have generated
    print(prog.get_code())


def process_entry_function(cursor, entry_func):
    func = find_elem(cursor, entry_func)
    if func is None:
        print('Did not found the entry function', file=sys.stderr)
        return


    text = get_code(func)
    print(text)
