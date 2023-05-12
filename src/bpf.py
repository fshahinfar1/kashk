class SK_SKB_PROG:
    def __init__(self):
        self.connection_state = []

    def add_connection_state(self, state):
        self.connection_state.append(state)

    def required_headers(self):
        return [
                # headers
                '#include <sys/types.h>',
                '#include <sys/socket.h>',
                '#include <linux/tcp.h>',
                '#include <linux/bpf.h>',
                '#include <bpf/bpf_helpers.h>',
                '#include <bpf/bpf_endian.h>',
                ]

    def license(self):
        return ['char _license[] SEC("license") = "GPL";',]

    def per_connection_state(self):
        return ([
                '/* Put state of each socket in this struct (This will be used in sockops.h as',
                ' * part of per socket metadata) */',
                'struct connection_state {',
                ] 
                + [s.get_c_code() for s in self.connection_state]
                + [
                '};',
                '#include "my_bpf/sockops.h"',
                ])


    def parser_prog(self):
        return [
                'SEC("sk_skb/stream_parser")',
                'int parser(struct __sk_buff *skb)',
                '{',
                '}',
                ]

    def verdict_prog(self):
        return [
                'SEC("sk_skb/stream_verdict")',
                'int verdict(struct __sk_buff *skb)',
                '{',
                '}',
                ]

    def get_code(self):
        code = ([]
                + self.required_headers()
                + self.per_connection_state()
                + self.parser_prog()
                + self.verdict_prog()
                + self.license()
                )
        return '\n'.join(code)
