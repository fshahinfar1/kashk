#include "./commons.h"

/* Moving a large object from stack to the BPF map */

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
int prog_1(struct xdp_md *xdp)
{
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	char obj[256];
	for (int i = 0; i < 256; i++) {
		obj[i] = (i * i) % 256;
	}
	if (data + 8 > data_end)
		return XDP_DROP;
	memcpy(data, obj, 8);
	return XDP_DROP;
}

SEC("xdp")
int prog_2(struct xdp_md *xdp)
{
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	const __u32 key = 0;
	struct item *it;
	char *obj;
	it = bpf_map_lookup_elem(&a_map, &key);
	if (it == NULL) {
		return XDP_DROP;
	}
	obj = it->data;
	for (int i = 0; i < 256; i++) {
		obj[i] = (i * i) % 256;
	}
	if (data + 8 > data_end)
		return XDP_DROP;
	memcpy(data, obj, 8);
	return XDP_DROP;
}
