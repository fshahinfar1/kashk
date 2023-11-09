#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <string.h>

struct resp {
	char *ptr;
	int size;
};

struct conn {
	char *rbuf;
	int rsize;
	struct resp resp;
	struct resp arr[3];
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


	c->resp.ptr = "Hello world!END\r\n";
	c->resp.size = strlen(c->resp.ptr);

	/* Test if owner of array access is parsed correctly */
	c->arr[0].size = 2;

	send(fd, c->resp.ptr, c->resp.size, 0);

	/* NOTE: I do not know how to solve the static analysis issue with
	 * sendmsg. I tackle this later.
	 * */
	/* struct iovec iovs[2]; */
	/* struct msghdr msg; */

	/* memset(&msg, 0, sizeof(msg)); */
	/* msg.msg_iov = iovs; */
	/* msg.msg_name = &addr; */
	/* msg.msg_namelen = sock_addr_size; */
	/* iovs[0].iov_base = c->resp.ptr; */
	/* iovs[0].iov_len = c->resp.size; */
	/* msg.msg_iovlen = 1; */
	/* sendmsg(fd, &msg, 0); */
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
	_c.rbuf = malloc(_c.rsize);
	void *arg = &_c;
}
