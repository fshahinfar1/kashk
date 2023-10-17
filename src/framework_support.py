import os


class InputOutputContext:
    INPUT_CPP_ASIO20 = 0
    INPUT_C_EPOLL = 1
    INPUT_C_LIBEVENT = 2

    HOOK_XDP = 'xdp'
    HOOK_SK_SKB = 'sk_skb'

    def __init__(self):
        self.input_file = ''
        self.bpf_out_file = ''
        self.user_out_file = ''
        self.entry_func = ''
        self.input_framework = None
        self.cflags = ''
        self.other_source_files = []
        self.bpf_hook = '_no_set_'

    def set_input(self, path):
        self.input_file = path
        if not self.bpf_out_file:
            self.bpf_out_file = '/tmp/bpf.c'
        if not self.user_out_file:
            _, in_file_ext = os.path.splitext(self.input_file)
            if in_file_ext == '.c':
                self.user_out_file = '/tmp/user.c'
            else:
                self.user_out_file = '/tmp/user.cpp'
        return self

    def set_user_output(self, path):
        self.user_out_file = path
        return self

    def set_entry_func(self, name):
        self.entry_func = name
        return self

    def set_bpf_output(self, path):
        self.bpf_out_file = path
        return self

    def set_cflags(self, flags):
        self.cflags = flags

    def set_framework(self, name):
        if name == 'libev':
            self.input_framework = InputOutputContext.INPUT_C_LIBEVENT
        elif name == 'poll':
            self.input_framework = InputOutputContext.INPUT_C_EPOLL
        elif name == 'asio':
            self.input_framework = InputOutputContext.INPUT_CPP_ASIO20
