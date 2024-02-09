#include "./commons.h"

struct item {
	char data[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key,  __u32);
	__type(value, struct item);
	__uint(max_entries, 1);
} a_map SEC(".maps");

SEC("xdp")
int prog(struct xdp_md *xdp)
{
	const int zero = 0;
	struct item *it;
	it = bpf_map_lookup_elem(&a_map, &zero);
	if (it  == NULL) return XDP_ABORTED;
	it->data[127] = 'f';
	return XDP_DROP;
}

