/*
 * This file defines a SOCK_OPS program for monitoring incomming connectios to
 * a server and adding tehm to SK_SKB programs.
 * */
#include "commons.h"
#include <linux/tcp.h>


#include "sockops_shared.h"
#include "internal_types.h"

struct {
	__uint(type,  BPF_MAP_TYPE_ARRAY);
	__type(key,   __u32);
	__type(value, struct conn_monitor_config);
	__uint(max_entries, 1);
} conn_monitor_config_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__type(key,   struct __five_tuple);
	__type(value, __u64);
	__uint(max_entries, MAX_CONN);
} sock_map SEC(".maps");
/* } sock_hash SEC(".maps"); */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key,   struct __five_tuple);
	__type(value, struct sock_context);
	__uint(max_entries, MAX_CONN);
} conn_ctx_map SEC(".maps");

/*
 * Given a bpf_sock fill the five_tuple structure
 * */
sinline
int __get_conn_id(struct bpf_sock *sk, struct __five_tuple *id)
{
	id->proto = sk->protocol;
	id->src_port = sk->src_port; /* host byte order */
	id->dst_port = sk->dst_port; /* network byte order */
	id->src_ip = sk->src_ip4;
	id->dst_ip = sk->dst_ip4;
	return 0;
}

sinline
int __new_connection(struct bpf_sock_ops *skops, struct tcphdr *tcp,
		struct __five_tuple *id)
{
	int ret;
	struct conn_monitor_config *conf;
	struct sock_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	ret = 0;
	conf = bpf_map_lookup_elem(&conn_monitor_config_map, &ret);
	if (!conf) {
		/* Should never happen */
		return -1;
	}
	if (tcp->dest != conf->port) {
		/* Ignore this */
		return -1;
	}
	/* Add the socket to the map */
	bpf_printk("regiseter new connection");
	ret = bpf_sock_hash_update(skops, &sock_map, id, BPF_NOEXIST);
	if (ret != 0) {
		bpf_printk("failed to insert socket to map");
		return -1;
	}
	/* Ask for sock close callback */
	ret = bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags |
			BPF_SOCK_OPS_STATE_CB_FLAG);

	/* Initialize socket context */
	bpf_map_update_elem(&conn_ctx_map, id, &ctx, BPF_NOEXIST);
	return 0;
}

SEC("sockops")
int monitor_connections(struct bpf_sock_ops *skops)
{
	int ret;
	void *data;
	void *data_end;
	struct tcphdr *tcp;
	struct __five_tuple id;

	if (skops->sk == NULL) {
		/* This should not happen */
		return 0;
	}

	data = (void *)(__u64)skops->skb_data;
	data_end = (void *)(__u64)skops->skb_data_end;
	tcp = data;
	if (skops->family != AF_INET || (void *)(tcp + 1) > data_end) {
		return 0;
	}

	ret = __get_conn_id(skops->sk, &id);
	if (ret != 0) {
		/* Failed to extract flow-id */
		return 0;
	}

	/* Check for socket close event */
	switch (skops->op) {
		case BPF_SOCK_OPS_STATE_CB:
			if (skops->args[1] == BPF_TCP_CLOSE) {
				bpf_map_delete_elem(&sock_map, &id);
			}
			break;
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			ret = __new_connection(skops, tcp, &id);
			if (ret != 0) {
				/* Failed */
				return 0;
			}
			break;
		default:
			break;
	}
	return 0;
}
