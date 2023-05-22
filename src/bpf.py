from utility import generate_struct_with_fields


class SK_SKB_PROG:
    def __init__(self):
        self.connection_state = []
        self._decs = set()
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
        if text not in self._decs:
            self._decs.add(text)
            self.declarations.append(text)

    def _per_connection_state(self):
        return ([
                '/* Put state of each socket in this struct (This will be used in sockops.h as',
                ' * part of per socket metadata) */',
                generate_struct_with_fields('connection_state', self.connection_state),
                '#include "my_bpf/sockops.h"',
                ])


    def _load_connection_state(self):
        return '''
struct sock_context *sock_ctx;

if (skb->sk == NULL) {
  bpf_printk("The socket reference is NULL");
  return SK_DROP;
}
sock_ctx = bpf_sk_storage_get(&sock_ctx_map, skb->sk, NULL, 0);
if (!sock_ctx) {
  bpf_printk("Failed to get socket context!");
  return SK_DROP;
}
'''


    def _parser_prog(self, body):
        return ([
                'SEC("sk_skb/stream_parser")',
                'int parser(struct __sk_buff *skb)',
                '{',
                ]
                + body
                + ['}']
                )

    def _verdict_prog(self, body):
        return ([
                'SEC("sk_skb/stream_verdict")',
                'int verdict(struct __sk_buff *skb)',
                '{',
                ]
                + body
                + ['}']
                )

