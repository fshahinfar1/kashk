#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <string.h>


/* This function is implemented in another file */
int func1(int a, int b);

struct resp {
	char *ptr;
	int size;
};

struct conn {
	char *rbuf;
	int rsize;
	struct resp resp;
};

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

	int x = func1(3, 81);
	c->resp.ptr = "Hello world!END\r\n";
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
