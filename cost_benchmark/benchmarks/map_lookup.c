#include "./commons.h"
#define REPEAT 10000

/* #define ARRAY 1 */
/* #define HASH 1 */
#define ON_STACK 1

/* #define KEY_8 */
/* #define KEY_16 */
#define KEY_32


struct item {
	char data[256];
	/* char data[4096]; */
};

#ifdef ARRAY
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	/* __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); */
	__type(key,  __u32);
	__type(value, struct item);
	__uint(max_entries, 1);
} a_map SEC(".maps");
#endif
#ifdef HASH
struct key {
#ifdef KEY_8
	char data[8];
#endif
#ifdef KEY_16
	char data[16];
#endif
#ifdef KEY_32
	char data[32];
#endif
};
struct {
	/* __uint(type, BPF_MAP_TYPE_HASH); */
	/* __uint(type, BPF_MAP_TYPE_PERCPU_HASH); */
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	/* __uint(type, BPF_MAP_TYPE_PERCPU_LRU_HASH); */
	__type(key,  struct key);
	__type(value, struct item);
	__uint(max_entries, 1);
} a_map SEC(".maps");
#endif

#ifndef ON_STACK
static long prog_loop(__u32 ii, void *_ctx)
{
#ifdef ARRAY
	const int zero = 0;
#endif
#ifdef HASH
	const struct key zero =  {
#ifdef KEY_8
		.data = "ilbcetep",
#endif
#ifdef KEY_16
		.data = "ilbcetepljnmqrpa",
#endif
#ifdef KEY_32
		.data = "ilbcetepljnmqrpazmuiujzknmjddqfk",
#endif
	};
#endif
	struct item *it;
	it = bpf_map_lookup_elem(&a_map, &zero);
	if (it  == NULL) return 1;
	it->data[127] = 'f';
	return 0;
}
#endif

static long prog_loop_stack(__u32 ii, void *_ctx)
{
	struct item *it = _ctx;
	if (it == NULL) return 1;
	it->data[127] = 'f';
	return 0;
}

SEC("xdp")
int prog(struct xdp_md *xdp)
{
#ifdef ON_STACK
	struct item it;
	__builtin_memset(&it, 0, sizeof(it));
	bpf_loop(REPEAT, prog_loop_stack, &it, 0);
#else
	bpf_loop(REPEAT, prog_loop, NULL, 0);
#endif
	return XDP_DROP;
}

