def bpf_ctx_bound_check(ref, index, data_end):
    return '\n'.join([
        f'if ((void *)({ref} + {index} + 1) > (void *){data_end}) {{',
        '  return 0;',
        '}\n'])
