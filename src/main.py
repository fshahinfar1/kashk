import argparse
from framework_support import InputOutputContext
from offload import generate_offload


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='path to the source file')
    parser.add_argument('func', help='name of the entry function')
    parser.add_argument('--out-bpf', help='store generated BPF program in this file', default=None)
    parser.add_argument('--out-user', help='store generated socket program in this file', default=None)
    parser.add_argument('--cflags', help='flags to pass to the compiler', default='')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()

    input_file = args.file
    out_user = args.out_user

    ctx = InputOutputContext()
    ctx.set_input(input_file)
    if out_user:
        ctx.set_user_output(out_user)
    if args.out_bpf:
        ctx.set_bpf_output(args.out_bpf)
    ctx.set_entry_func(args.func)
    ctx.set_cflags(args.cflags)

    generate_offload(ctx)


if __name__ == '__main__':
    main()
