from utility import generate_struct_with_fields


class SK_SKB_PROG:
    def __init__(self):
        self.connection_state = []
        self.declarations = []
        self.parser_code = []
        self.verdict_code = []
        self.headers = [
                # headers
                '#include <sys/types.h>',
                '#include <sys/socket.h>',
                '#include <linux/tcp.h>',
                '#include <linux/bpf.h>',
                '#include <bpf/bpf_helpers.h>',
                '#include <bpf/bpf_endian.h>',
                ]
        self.license = 'GPL'


    def add_connection_state(self, state):
        self.connection_state.append(state)

    def add_declaration(self, text):
        self.declarations.append(text)

    def per_connection_state(self):
        return ([
                '/* Put state of each socket in this struct (This will be used in sockops.h as',
                ' * part of per socket metadata) */',
                generate_struct_with_fields('connection_state', self.connection_state),
                '#include "my_bpf/sockops.h"',
                ])


    def parser_prog(self):
        return ([
                'SEC("sk_skb/stream_parser")',
                'int parser(struct __sk_buff *skb)',
                '{',
                ]
                + self.parser_code
                + ['}']
                )

    def verdict_prog(self):
        return ([
                'SEC("sk_skb/stream_verdict")',
                'int verdict(struct __sk_buff *skb)',
                '{',
                ]
                + self.verdict_code
                + ['}']
                )

    def get_code(self):
        code = ([]
                + self.headers
                + self.declarations
                + self.per_connection_state()
                + self.parser_prog()
                + self.verdict_prog()
                + [f'char _license[] SEC("license") = "{self.license}";',]
                )
        return '\n'.join(code)
