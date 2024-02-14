#include "./commons.h"
#define REPEAT 10000

struct loop_ctx {
	struct xdp_md *xdp;
};

static long prog_loop(__u32 ii, void *_ctx)
{
	struct loop_ctx *ctx = _ctx;
	__prepare_headers_before_send(ctx->xdp);
	return 0;
}

SEC("xdp")
int prog(struct xdp_md *xdp)
{
	struct loop_ctx tmp ={
		.xdp = xdp,
	};
	bpf_loop(REPEAT, prog_loop, &tmp, 0);
	return XDP_DROP;
}
