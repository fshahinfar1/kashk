#include "commons.h"
#define MAX_REPEAT 10000

static long prog_1_loop(__u32 ii, void *_ctx)
{
	char *obj = _ctx;
	for (int i = 0; i < 256; i++) {
		obj[i] = (i * i) % 0xfff1;
	}
	return 0;
}

SEC("xdp")
int prog_1(struct xdp_md *xdp)
{
	char obj[256] = {};
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	bpf_loop(MAX_REPEAT, prog_1_loop, obj, 0);
	if (data + 8 > data_end)
		return XDP_DROP;
	memcpy(data, obj, 8);
	return XDP_DROP;
}

static long prog_2_loop(__u32 ii, void *_ctx)
{
	char *obj = _ctx;
	for (int i = 0; i < 256; i++) {
		/* A silly bound check */
		/* NOTE: the bound check does not check 256 because the
		 * compiler might optimize it. The i is checked to be
		 * less than 256 so the check will always be false if
		 * we check for obj+256.
		 *
		 * Both paths should have the same instructions
		 * */
		if (obj + i + 1 > obj + 128) {
			obj[i] = (i * i) % 0xff01;
			continue;
		} else {
			obj[i] = (i * i) % 0xfff1;
			continue;
		}
	}
	return 0;
}

SEC("xdp")
int prog_2(struct xdp_md *xdp)
{
	char obj[256] = {};
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	bpf_loop(MAX_REPEAT, prog_2_loop, obj, 0);
	if (data + 8 > data_end)
		return XDP_DROP;
	memcpy(data, obj, 8);
	return XDP_DROP;
}
