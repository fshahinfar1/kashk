#include "commons.h"
#define MAX_REPEAT 10000

SEC("xdp")
int prog_1(struct xdp_md *xdp)
{
	char obj[256] = {};
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	for (int i = 0; i < 256; i++) {
		obj[i] = (i * i) % 0xfff1;
	}
	if (data + 8 > data_end)
		return XDP_DROP;
	memcpy(data, obj, 8);
	return XDP_DROP;
}

SEC("xdp")
int prog_2(struct xdp_md *xdp)
{
	char obj[256] = {};
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
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


	if (data + 8 > data_end)
		return XDP_DROP;
	memcpy(data, obj, 8);
	return XDP_DROP;
}
