#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

/* #include "apex_memmove.h" */

#define REPEAT 100

/* #define MEMCPY memcpy */
/* #define MEMCPY apex_memcpy */
#define MEMCPY naive_memcpy


void *naive_memcpy(void *dst, void *src, size_t size)
{
	uint8_t *d = dst, *s = src;
	for (size_t i = 0; i < size; i++) {
		d[i] = s[i];
	}
	return dst;
}

struct item {
	char data[1000];
};

static inline uint64_t get_ns(void)
{
	int ret;
	uint64_t ns;
	struct timespec tp;
	ret = clock_gettime(CLOCK_MONOTONIC, &tp);
	if (ret != 0) {
		return 0;
	}
	ns = tp.tv_sec * 1000000000 + tp.tv_nsec;
	return ns;
}

static void do_exp(struct item *arr, struct item *d)
{
	for (int i = 1; i < (REPEAT + 1); i++) {
		struct item *it = &arr[i];
		MEMCPY(it->data, d->data, 1000);
	}
}

int main(int argc, char *argv[])
{
	uint64_t begin, duration;
	/* struct item *arr = calloc((REPEAT + 1), sizeof(struct item)); */
	struct item *arr = malloc((REPEAT + 1) * sizeof(struct item));
	if (arr == NULL) {
		printf("failed to allocate memory!\n");
		return -1;
	}
	struct item *d = &arr[0];

	for (int i = 0; i < 1000; i++) {
		d->data[i] = 'a' + (i % 26);
	}

	const int repeat = 10000;
	begin = get_ns();
	for (int i = 0; i < repeat; i++) {
		do_exp(arr, d);
	}
	duration = get_ns() - begin;
	uint64_t t1 = duration / repeat;
	uint32_t t2 = t1 / REPEAT;
	uint32_t t2r = t1 % REPEAT;
	printf("duration: %lu (%d r:%d)\n", t1, t2, t2r);

	int x = 0;
	for (int i = 0; i < REPEAT; i++) {
		for (int j = 0; j < 1000; j++) {
			x += (unsigned int)arr[i].data[j];
		}
	}
	if (x == 1234) return 1;
	return 0;
}
