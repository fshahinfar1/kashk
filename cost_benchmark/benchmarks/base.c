#include "./commons.h"
SEC("xdp")
int xdp_prog(struct xdp_md *xdp)
{
	return XDP_DROP;
}
