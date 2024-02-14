#include "./commons.h"
#define REPEAT 10000
/* Moving a large object from stack to the BPF map */
/*  Moving large objects to BPF map seems to be good :) ?!
 *  Probably because the same memory region is reused multiple times.
 *  But if we want to reinitialize the whole memory everytime (set to
 *  zero), it would be bad be cause we would be doing more work.
 * */

struct item {
	char data[256];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key,  __u32);
	__type(value, struct item);
	__uint(max_entries, 1);
} a_map SEC(".maps");

struct loop_ctx {
	__u64 res;
	__u8 err;
};

static long prog_1_loop(__u32 ii, void *_ctx)
{
	struct loop_ctx *ctx = _ctx;
	char obj[256] = {};
	for (int i = 0; i < 256; i++) {
		obj[i] = (i * i) % 256;
	}
	ctx->res = *((__u64 *)&obj[127]);
	return 0;
}

SEC("xdp")
int prog_1(struct xdp_md *xdp)
{
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	struct loop_ctx tmp = {};
	bpf_loop(REPEAT, prog_1_loop, &tmp, 0);
	if (tmp.err)
		return XDP_DROP;
	if (data + 8 > data_end)
		return XDP_DROP;
	memcpy(data, &tmp.res, 8);
	return XDP_DROP;
}

static long prog_2_loop(__u32 ii, void *_ctx)
{
	struct loop_ctx *ctx = _ctx;
	const __u32 key = 0;
	struct item *it;
	char *obj;
	it = bpf_map_lookup_elem(&a_map, &key);
	if (it == NULL) {
		ctx->err = 1;
		return 1;
	}
	obj = it->data;
	 /* memset(obj, 0, 256); */
	for (int i = 0; i < 256; i++) {
		obj[i] = (i * i) % 256;
	}
	ctx->res = *((__u64 *)&obj[127]);
	return 0;
}

SEC("xdp")
int prog_2(struct xdp_md *xdp)
{
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	struct loop_ctx tmp = {};
	bpf_loop(REPEAT, prog_2_loop, &tmp, 0);
	if (tmp.err)
		return XDP_DROP;
	if (data + 8 > data_end)
		return XDP_DROP;
	memcpy(data, &tmp.res, 8);
	return XDP_DROP;
}
