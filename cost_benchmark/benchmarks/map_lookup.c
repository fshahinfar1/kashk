#include "./commons.h"
#define REPEAT 10000

struct item {
	char data[256];
	/* char data[4096]; */
};

struct {
	/* __uint(type, BPF_MAP_TYPE_ARRAY); */
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key,  __u32);
	__type(value, struct item);
	__uint(max_entries, 1);
} a_map SEC(".maps");

static long prog_loop(__u32 ii, void *_ctx)
{
	const int zero = 0;
	struct item *it;
	it = bpf_map_lookup_elem(&a_map, &zero);
	if (it  == NULL) return XDP_ABORTED;
	it->data[127] = 'f';
	return 0;
}

SEC("xdp")
int prog(struct xdp_md *xdp)
{
	bpf_loop(REPEAT, prog_loop, NULL, 0);
	return XDP_DROP;
}

