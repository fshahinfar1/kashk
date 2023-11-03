#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

struct conn {
	char buf[128];
	int size;
};

struct request {
	int type;
	int quety;
};

void do_read(int fd, char *buf, int len, int *_size)
{
	int size = read(fd, buf, len, 0);
	*_size = size;
}

int main(int argc, char *argv[])
{
	int fd;
	int size;
	int x;
	char buf[128];
	char *ptr;
	struct conn t;
	struct conn *c = &t;
	struct request *req1;
	struct request *req2;
	struct request *req3;

	/* Test 1: Array */
	fd = 0;
	do_read(fd, buf, 128, &size);
	/* The BPF packet context should spill from the do_read scope to this
	 * scope */
	req1 = (void *)buf;
	/* I expect the tool generate a bound check for this access */
	x = req1->type;

	/* Test 2: struct pointer */
	do_read(fd, c->buf, 128, &c->size);
	/* The BPF packet context should spill from the do_read scope to this
	 * scope */
	req2 = (void *)c->buf;
	/* I expect the tool generate a bound check for this access */
	x = req2->type;

	/* Test 3: Pointer */
	ptr = buf;
	do_read(fd, ptr, 128, &size);
	req3 = (void *)ptr;
	/* I expect the tool generate a bound check for this access */
	x = req3->type;

	return 0;
}
