def bpf_get_data(buf, skb='skb'):
    return f'{buf} = (void *)(__u64){skb}->data;\n'


def bpf_ctx_bound_check(ref, index, data_end):
    return '\n'.join([
        f'if ((void *)({ref} + {index} + 1) > (void *){data_end}) {{',
        '  return 0;',
        '}\n'])


def bpf_ctx_bound_check_bytes(ref, size, data_end):
    return '\n'.join([
        f'if ((void *){ref} + {size} + 1 > (void *){data_end}) {{',
        '  return 0;',
        '}\n'])


def memcpy_internal_defs():
    return '''#ifndef memcpy
#define memcpy(d, s, len) __builtin_memcpy(d, s, len)
#endif

#ifndef memmove
#define memmove(d, s, len) __builtin_memmove(d, s, len)
#endif'''


def license_text(license):
    return f'char _license[] SEC("license") = "{license}";'


def load_shared_object_code():
    return '''struct shared_state *shared = NULL;
{
  int zero = 0;
  shared = bpf_map_lookup_elem(&shared_map, &zero);
}
'''

def send_response_template(buf, write_size, skb='skb'):
    code = [
        f'__adjust_skb_size({skb}, {write_size});',
        f'if (((void *)(__u64){skb}->data + {write_size})  > (void *)(__u64){skb}->data_end) {{',
        f'  return SK_DROP;',
        '}',
        f'memcpy((void *)(__u64){skb}->data, {buf}, {write_size});',
        'return bpf_sk_redirect_map({skb}, &sock_map, sock_ctx->sock_map_index, 0);',
        ]
    text = '\n'.join(code)
    return text
