import sys
import argparse
import yaml

from log import error
from framework_support import InputOutputContext
from offload import generate_offload

class Args:
    def __init__(self):
        pass


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('file', help='path to the source file containing the main loop')
    parser.add_argument('func', help='name of the entry function')
    parser.add_argument('--sources', nargs='*', help='other c files which provide the functions and data-structures')
    parser.add_argument('--out-bpf', help='store generated BPF program in this file', default=None)
    parser.add_argument('--out-user', help='store generated socket program in this file', default=None)
    parser.add_argument('--cflags', help='flags to pass to the compiler', default='')
    args = parser.parse_args()
    return args

def parse_args_yaml():
    parser = argparse.ArgumentParser()
    parser.add_argument('yaml_file', help='path to the yaml file containing the project config')
    args = parser.parse_args()
    try:
        with open(args.yaml_file, 'r') as f:
            config = yaml.load(f, Loader=yaml.FullLoader)
    except Exception as e:
        error('Failed to load yaml file')
        error(e)
        sys.exit(1)

    assert 'main' in config, 'The main field must be defined in the yaml file'
    assert 'entry' in config, 'Them entry field must be defined in the yaml file'
    obj = Args()
    obj.file = config['main']
    obj.func = config['entry']
    obj.sources = config.get('sources', [])
    obj.out_bpf = config.get('out_bpf')
    obj.out_user = config.get('out_user')
    obj.cflags = config.get('cflags', '')
    assert isinstance(obj.cflags, str)
    return obj


def main():
    # args = parse_args()
    args = parse_args_yaml()

    input_file = args.file
    out_user = args.out_user

    ctx = InputOutputContext()
    ctx.set_input(input_file)
    ctx.other_source_files = args.sources
    if out_user:
        ctx.set_user_output(out_user)
    if args.out_bpf:
        ctx.set_bpf_output(args.out_bpf)
    ctx.set_entry_func(args.func)
    ctx.set_cflags(args.cflags)

    generate_offload(ctx)


if __name__ == '__main__':
    main()
