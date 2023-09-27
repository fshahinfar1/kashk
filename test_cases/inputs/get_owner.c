#include <stdio.h>
#include <stdlib.h>

#define ITEM_CHUNKED ((1U) << 2)

typedef struct item {
	int it_flags;
} item;

typedef struct record {
	void *item;
} record;

int main(int argc, char *argv[])
{
	/*
	 * The goal of this test is to successfully parse the complex
	 * object ownership relations. That is, record has item which is of
	 * type ...
	 * */
	/* const unsigned int ITEM_CHUNKED = 1U << 2; */
	record *c = calloc(1, sizeof(record));
	c->item = calloc(1, sizeof(item));
	((item *)c->item)->it_flags = 0xff;

	if ((((item *)c->item)->it_flags & ITEM_CHUNKED) == 0) {
		printf("hello world!\n");
	}
	return 0;
}
