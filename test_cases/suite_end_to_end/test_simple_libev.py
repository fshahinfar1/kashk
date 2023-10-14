import os
import sys
import clang.cindex as clang

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
src_dir  = os.path.join(root_dir, '../src')
sys.path.insert(0, root_dir)
sys.path.insert(0, src_dir)

from framework_support import InputOutputContext
from offload import generate_offload
from utility import find_elems_of_kind


def main():
    input_file = os.path.join(root_dir, 'inputs/end_to_end/simple_libev_xdp.c')
    entry_func = 'event_handler'

    ctx = InputOutputContext()
    ctx.bpf_hook = 'xdp'
    ctx.set_input(input_file)
    ctx.other_source_files = []
    ctx.set_user_output('/tmp/test_user.c')
    ctx.set_bpf_output('/tmp/test_bpf.c')
    ctx.set_entry_func(entry_func)
    ctx.set_cflags('')
    ctx.input_framework = InputOutputContext.INPUT_C_LIBEVENT

    info = generate_offload(ctx)

    # Report the generated BPF code
    print('Generated BPF Code:')
    with open(ctx.bpf_out_file, 'r') as f:
        print(f.read())
    print('---------------------------------------')

    # TODO: run tests on info or out file


if __name__ == '__main__':
    main()
