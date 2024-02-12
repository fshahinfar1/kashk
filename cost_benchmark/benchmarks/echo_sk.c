#include "./commons.h"

struct connection_state { };
#include "sockops.h"

SEC("sk_skb/stream_parser")
int parser(struct __sk_buff *ctx)
{
	return ctx->len;
}

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
	const __u32 zero = 0;
	/* bpf_printk("here"); */
	int ret = bpf_sk_redirect_map(skb, &sock_map, zero, 0);
	/* bpf_printk("ret: %d", ret); */
	return ret;
}

