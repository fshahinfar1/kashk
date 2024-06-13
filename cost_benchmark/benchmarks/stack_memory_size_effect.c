#include "./commons.h"
#define DO_NOT_OPTIMIZE __attribute__((optnone))
#define UNUSED          __attribute__((unused))
#define SIZE 400


SEC("xdp")
int DO_NOT_OPTIMIZE prog(struct xdp_md *xdp)
{
	void *data, *data_end;
	data = (void *)(__u64)xdp->data;
	data_end = (void *)(__u64)xdp->data_end;
	__u16 *p = data;
	__u8 variable[SIZE];
	if (p + 1 > data_end)
		return XDP_ABORTED;
	if (*p == 0x12) {
		bpf_printk("This path must not happen");
		memset(variable, 0, SIZE);
	}
	return XDP_DROP;
}
