#include "./commons.h"

struct connection_state { };
#include "sockops.h"

SEC("sk_skb/stream_parser")
int parser(struct __sk_buff *ctx)
{
	/* bpf_printk("parser"); */
	return ctx->len;
}

SEC("sk_skb/stream_verdict")
int verdict(struct __sk_buff *skb)
{
	/* return SK_PASS; */

	/* bpf_printk("xxx"); */
	/* if (bpf_skb_pull_data(skb, skb->len) != 0) { */
	/* 	bpf_printk("failed to pull data"); */
	/* 	return SK_DROP; */
	/* } */

	const __u32 zero = 0;
	/* bpf_printk("here"); */
	int ret = bpf_sk_redirect_map(skb, &sock_map, zero, 0);
	/* bpf_printk("ret: %d", ret); */
	return ret;
}

