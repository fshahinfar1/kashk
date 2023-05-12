import argparse
from offload import generate_offload


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='path to the source file')
    parser.add_argument('func', help='name of the entry function')
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    generate_offload(args.file, args.func)


if __name__ == '__main__':
    main()
