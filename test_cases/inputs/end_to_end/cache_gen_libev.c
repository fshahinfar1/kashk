#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <string.h>


struct cached_resp {
	char ptr[1024];
	int size;
};

struct resp {
	char *ptr;
	int size;
};

struct conn {
	char *rbuf;
	int rsize;
	struct resp resp;
};

/*                      id,           key_kind,   key_t, key_size, value_kind, value_t,            value_size */
__ANNOTATE_DEFINE_CACHE("main_cache", BYTE_ARRAY, "char", "0",       STRUCT,   "struct cached_resp", "1028")

/* This is the function we want to memoize.
 *
 * Since the body of the function is not provided it would fail fallback to
 * userspace when this function is called.
 * */
char *lookup_hashtable(char *key, int size);

void event_handler(int fd, short which, void *arg)
{
	int size;
	struct conn *c = arg;
	struct sockaddr_in addr;
	socklen_t sock_addr_size = sizeof(addr);

	size = recvfrom(fd, c->rbuf, c->rsize, 0, (struct sockaddr *)&addr, &sock_addr_size);
	if (size < 8) {
		return;
	}


	/* NOTE: The value reference should be defined before CACHE annotation ! */
	void *val;
	char *key = c->rbuf;
	int key_size = 8;
	__ANNOTATE_BEGIN_CACHE("main_cache", "key", "key_size", "val")
	val = lookup_hashtable(key, key_size);
	__ANNOTATE_END_CACHE("main_cache")

	c->resp.ptr = val;
	c->resp.size = strlen(c->resp.ptr);
	send(fd, c->resp.ptr, c->resp.size, 0);
}

int main()
{
	struct conn c;
	c.rsize = 1024;
	c.rbuf = malloc(c.rsize);
	event_handler(0, 0, &c);
	return 0;
}

void _prepare_event_handler_args(void)
{
	/* This is telling me how to prepare the event handler */
	int fd = 0;
	short which = 0;
	struct conn _c;
	_c.rsize = 1024;
	_c.rbuf = malloc(1024);
	void *arg = &_c;
}
