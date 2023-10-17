import os
import sys
import clang.cindex as clang
import subprocess

curdir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.join(curdir, '..')
src_dir  = os.path.abspath(os.path.join(root_dir, '../src'))
script_dir = os.path.abspath(os.path.join(root_dir, '../compile_scripts'))
sys.path.insert(0, root_dir)
sys.path.insert(0, src_dir)

from framework_support import InputOutputContext
from offload import generate_offload
from utility import find_elems_of_kind


def main():
    others = []
    others = list(map(lambda x: os.path.join(root_dir,'inputs/end_to_end/', x), others))
    input_file = os.path.join(root_dir, 'inputs/end_to_end/', 'cache_gen_libev.c')
    entry_func = 'event_handler'
    bpf_out = '/tmp/test_bpf.c'

    ctx = InputOutputContext()
    ctx.bpf_hook = 'xdp'
    ctx.set_input(input_file)
    ctx.other_source_files = others
    ctx.set_user_output('/tmp/test_user.c')
    ctx.set_bpf_output(bpf_out)
    ctx.set_entry_func(entry_func)
    ctx.set_cflags('')
    ctx.input_framework = InputOutputContext.INPUT_C_LIBEVENT

    info = generate_offload(ctx)

    # Report the generated BPF code
    # print('Generated BPF Code:')
    # with open(ctx.bpf_out_file, 'r') as f:
    #     print(f.read())
    # print('---------------------------------------')
    # print('Generated User Code:')
    # with open(ctx.user_out_file, 'r') as f:
    #     print(f.read())
    # print('---------------------------------------')

    #bpf_out_file print(info.user_prog.graph.paths.code.children)
    bpf_bin_out = '/tmp/test_bpf.o'
    compile_script = os.path.join(script_dir, 'compile_bpf_source.sh')
    cmd = ['/bin/bash', compile_script, bpf_out, bpf_bin_out]
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ret = proc.returncode
    assert ret == 0, f'The generated source code should compile (ret code: {ret})'

    load_script = os.path.join(script_dir, 'load.sh')
    cmd = ['/bin/bash', load_script, bpf_bin_out]
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ret = proc.returncode
    assert ret == 0, f'The BPF program should pass the verifier'


if __name__ == '__main__':
    main()
