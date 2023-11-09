#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

struct conn {
	char buf[128];
	int size;
};

void access_data(struct conn *c)
{
	int x = c->buf[0];
}

void process_event(int fd, struct conn *c)
{
	c->size = read(fd, c->buf, 128);
	access_data(c);
}

int main(int argc, char *argv[])
{
	struct conn c = {};
	process_event(0, &c);
	return 0;
}

void _prepare_event_handler_args(void)
{
	struct conn *c;
	int fd;
	fd = 0;
	c = malloc(132);
}
