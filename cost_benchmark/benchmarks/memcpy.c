#define USE_KFUNC 1

#ifdef USE_KFUNC
#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#else
#include "./commons.h"
#endif

#define REPEAT 100

#ifdef USE_KFUNC
/* NOTE: please do not forget to add __ksym :) */
extern long my_kfunc_memcpy(void *dst, __u32 dst__sz, void *src, __u32 src__sz) __ksym;
/* #define MEMCPY(...) my_kfunc_memcpy(__VA_ARGS__) */
char _license[] SEC("license") = "GPL";
#else
#define MEMCPY(...) memcpy(__VA_ARGS__)
#endif

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

/* static struct item a; */
/* static struct item b; */

static long exp_loop(__u32 i, void *_ctx)
{
	loop_ctx_t *ctx = _ctx;
	int ii = i + 1;
	struct item *it = bpf_map_lookup_elem(&a_map, &ii);
	if (it == NULL) {
		ctx->err = 1;
		return 1;
	}
#ifdef USE_KFUNC
	my_kfunc_memcpy(it->data, sizeof(it->data), ctx->d->data, sizeof(ctx->d->data));
#else
	MEMCPY(it->data, ctx->d->data, 1000);
#endif
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

	i = 1;
	struct item *it = bpf_map_lookup_elem(&a_map, &i);
	if (it == NULL) { return -1; }
	/* memcpy(&it->data, d->data, 1000); */
	/* memcpy(&b, d->data, 1000); */
	/* memcpy(it->data, &a, 1000); */
	/* memcpy(&b, &a, 1000); */

	/* if (b.data[2] == 'c') return 1; */
	return 0;
}
