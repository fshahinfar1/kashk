#include "commons.h"

SEC("xdp")
int prog_1(struct xdp_md *xdp)
{
	char obj[256] = {};
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
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
	char obj[256] = {};
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	for (int i = 0; i < 256; i++) {
		/* A silly bound check */
		if (obj + i + 1 > obj + 256) {
			break;
		}
		obj[i] = (i * i) % 256;
	}
	if (data + 8 > data_end)
		return XDP_DROP;
	memcpy(data, obj, 8);
	return XDP_DROP;
}
