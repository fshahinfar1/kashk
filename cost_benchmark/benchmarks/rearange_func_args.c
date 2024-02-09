#include "./commons.h"

struct args {
	int a;
	int b;
	int c;
};

static inline
int f1(int a, int b, int c)
{
	return a + b + c;
}

static inline
int f2(struct args *a)
{
	return a->a + a->b + a->c;
}

int f3(int a, int b, int c, char *flag)
{
	int tmp = a + b + c;
	if (tmp % 2 == 0)
		*flag = 1;
	return tmp;
}

SEC("xdp")
int prog_1(struct xdp_md *xdp)
{
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	int *ptr = data;
	if (ptr + (4 * sizeof(int)) > data_end) {
		return XDP_ABORTED;
	}
	for (int i = 0; i < 256; i++) {
		ptr[3] = f1(ptr[0], ptr[1], ptr[2]);
	}
	return XDP_DROP;
}

SEC("xdp")
int prog_2(struct xdp_md *xdp)
{
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	int *ptr = data;
	if (ptr + (4 * sizeof(int)) > data_end) {
		return XDP_ABORTED;
	}
	struct args a = {
		.a = ptr[0],
		.b = ptr[1],
		.c = ptr[2],
	};
	ptr[3] = f2(&a);
	return XDP_DROP;
}

SEC("xdp")
int prog_3(struct xdp_md *xdp)
{
	void *data = (void *)(__u64)xdp->data;
	void *data_end = (void *)(__u64)xdp->data_end;
	int *ptr = data;
	char flag = 0;
	if (ptr + (4 * sizeof(int)) > data_end) {
		return XDP_ABORTED;
	}
	for (int i = 0; i < 256; i++) {
		int tmp = f3(ptr[0], ptr[1], ptr[2], &flag);
		if (flag == 0) {
			return XDP_ABORTED;
		}
		ptr[3] = tmp;
	}
	return XDP_DROP;
}
