#include "./commons.h"
#define REPEAT 10000
/* Moving a large object from stack to the BPF map */
/*  Moving large objects to BPF map seems to be good :) ?!
 *  Probably because the same memory region is reused multiple times.
 *  But if we want to reinitialize the whole memory everytime (set to
 *  zero), it would be bad be cause we would be doing more work.
 * */

#define VALUE_SIZE 256

struct item {
	char data[VALUE_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key,  __u32);
	__type(value, struct item);
	__uint(max_entries, 1);
} a_map SEC(".maps");

struct loop_ctx {
	__u64 res;
	__u8 err;
};

SEC("xdp")
int prog_1(struct xdp_md *xdp)
{
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	char obj[VALUE_SIZE];
	__u64 res;
	int i;
	/* memset(obj, 0, sizeof(obj)); */
	for (i = 0; i < VALUE_SIZE; i++) {
		obj[i] = (i * i) % VALUE_SIZE;
	}
	res = *((__u64 *)&obj[0]);
	if (data + 8 > data_end)
		return XDP_DROP;
	memcpy(data, &res, 8);
	return XDP_DROP;
}

SEC("xdp")
int prog_2(struct xdp_md *xdp)
{
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	const __u32 key = 0;
	struct item *it;
	char *obj;
	__u64 res;
	int i;
	it = bpf_map_lookup_elem(&a_map, &key);
	if (it == NULL)
		return XDP_DROP;
	obj = it->data;
	/* memset(obj, 0, VALUE_SIZE); */
	for (i = 0; i < VALUE_SIZE; i++) {
		obj[i] = (i * i) % VALUE_SIZE;
	}
	res = *((__u64 *)&obj[0]);
	if (data + 8 > data_end)
		return XDP_DROP;
	memcpy(data, &res, 8);
	return XDP_DROP;
}
