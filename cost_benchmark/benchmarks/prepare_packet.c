#include "./commons.h"
SEC("xdp")
int prog(struct xdp_md *xdp)
{
	__prepare_headers_before_send(xdp);
	return XDP_DROP;
}
