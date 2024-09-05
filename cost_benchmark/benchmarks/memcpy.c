#include "./commons.h"

#define REPEAT 100

struct item {
	char data[1000];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key,  __u32);
	__type(value, struct item);
	__uint(max_entries, REPEAT + 1);
} a_map SEC(".maps");

typedef struct {
	struct item *d;
	int err;
} loop_ctx_t;

static long exp_loop(__u32 i, void *_ctx)
{
	loop_ctx_t *ctx = _ctx;
	int ii = i + 1;
	struct item *it = bpf_map_lookup_elem(&a_map, &ii);
	if (it == NULL) {
		ctx->err = 1;
		return 1;
	}
	memcpy(it->data, ctx->d->data, 1000);
	return 0;
}

SEC("xdp")
int prog(struct xdp_md *xdp)
{
	int i;
	struct item *d;
	i = 0;
	d = bpf_map_lookup_elem(&a_map, &i);
	if (d == NULL) { return -1; }
	loop_ctx_t c = {
		.d = d,
		.err = 0,
	};
	bpf_loop(REPEAT, exp_loop, &c, 0);
	if (c.err != 0) { return -1; }
	return 0;
}
