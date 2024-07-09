#include "./commons.h"
#define REPEAT 100000

/*
 * Parameters controling the type of experiment
 * */

/* -- Map type -- */
#define ARRAY 1
/* #define HASH 1 */
/* #define LRU 1 */
/* #define ON_STACK 1 */

/* -- Key size -- */
#define KEY_4
/* #define KEY_8 */
/* #define KEY_16 */
/* #define KEY_32 */

/* -- Use per cpu -- */
#define PERCPU 1

/* ---------------------------------------- */


struct item {
	char data[256];
	/* char data[4096]; */
} __attribute__((packed));

typedef struct {
	int err;
	struct item *i;
} exp_ctx_t;

#if defined ARRAY
struct {
#ifdef PERCPU
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
#else
	__uint(type, BPF_MAP_TYPE_ARRAY);
#endif
	__type(key,  __u32);
	__type(value, struct item);
	__uint(max_entries, 1);
} a_map SEC(".maps");

#elif defined HASH || defined LRU
struct key {
#if  defined KEY_4
	char data[4];
#elif defined KEY_8
	char data[8];
#elif defined KEY_16
	char data[16];
#elif defined KEY_32
	char data[32];
#endif /* Size of the key */
} __attribute__((packed));

struct {
#ifdef HASH
	/* Hash table */
#ifdef PERCPU
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif /* Per cpu or normal version */
#else
	/* LRU map */
#ifdef PERCPU
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#endif /* Per cpu or normal version */
#endif /* Hash table or LRU */
	__type(key,  struct key);
	__type(value, struct item);
	__uint(max_entries, 1);
} a_map SEC(".maps");
#elif defined RING
#endif /* End of selecting the map type */

#ifndef ON_STACK
static long prog_loop(__u32 ii, void *_ctx)
{
	exp_ctx_t *ctx = _ctx;
#ifdef ARRAY
	const int zero = 0;
#elif defined HASH || defined LRU
	const struct key zero =  {
#if   defined KEY_4
		.data = "ilbc",
#elif defined KEY_8
		.data = "ilbcetep",
#elif defined KEY_16
		.data = "ilbcetepljnmqrpa",
#elif defined KEY_32
		.data = "ilbcetepljnmqrpazmuiujzknmjddqfk",
#endif /* Deciding the key size */
	};
#endif /* Chcekinf if array or hash */

	struct item *it;
	it = bpf_map_lookup_elem(&a_map, &zero);
	if (it  == NULL) {
		ctx->err = 1;
		return 1;
	}
	it->data[127] = 'f';
	return 0;
}
#endif

#ifdef ON_STACK
static long prog_loop_stack(__u32 ii, void *_ctx)
{
	exp_ctx_t *ctx = _ctx;
	struct item *it = ctx->i;
	if (it == NULL) {
		ctx->err = 1;
		return 1;
	}
	it->data[127] = 'f';
	return 0;
}
#endif

SEC("xdp")
int prog(struct xdp_md *xdp)
{
	exp_ctx_t c;
	__builtin_memset(&c, 0, sizeof(c));
#ifdef ON_STACK
	struct item it;
	__builtin_memset(&it, 0, sizeof(it));
	c.i = &it;
	bpf_loop(REPEAT, prog_loop_stack, &c, 0);
#else
	bpf_loop(REPEAT, prog_loop, &c, 0);
#endif
	if (c.err != 0)
		return 127;
	return XDP_DROP;
}
