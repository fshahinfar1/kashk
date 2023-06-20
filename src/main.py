import argparse
from offload import generate_offload


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='path to the source file')
    parser.add_argument('func', help='name of the entry function')
    parser.add_argument('--out-bpf', help='store generated BPF program in this file', default='/tmp/bpf.c')
    parser.add_argument('--out-user', help='store generated socket program in this file', default='/tmp/user.cpp')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    generate_offload(args.file, args.func,
            out_bpf=args.out_bpf, out_user=args.out_user)


if __name__ == '__main__':
    main()
