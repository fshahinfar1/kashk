#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>

#define BUFSIZE 128

#ifndef __ANNOTATE_LOOP
#define __ANNOTATE_LOOP(x)
#endif

void not_offloadable_func(void);

void costly_func(char *buf, short size)
{
	for (int i = 0; i < size; i++) {
		buf[i] = (buf[i] * buf[i]) % 256;
		buf[i] = (buf[i] * buf[i]) % 256;
		buf[i] = (buf[i] * buf[i]) % 256;
		buf[i] = (buf[i] * buf[i]) % 256;
		buf[i] = (buf[i] * buf[i]) % 256;
		buf[i] = (buf[i] * buf[i]) % 256;
	}
}

int main(int argc, char *argv[])
{
	int fd;
	struct sockaddr_in sk_addr, addr;
	socklen_t addr_len;
	inet_pton(AF_INET, "127.0.0.1", &(sk_addr.sin_addr));
	sk_addr.sin_port = htons(8080);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	bind(fd, (struct sockaddr *)&sk_addr, sizeof(sk_addr));
	while (1) {
		char buf[BUFSIZE];
		int ret = recvfrom(fd, buf, BUFSIZE, 0,
				(struct sockaddr *)&addr, &addr_len);
		char *tmp = malloc(1024);
		__ANNOTATE_LOOP(128)
		memcpy(&tmp[0 * BUFSIZE], buf, ret);
		__ANNOTATE_LOOP(128)
		memcpy(&tmp[1 * BUFSIZE], buf, ret);
		__ANNOTATE_LOOP(128)
		memcpy(&tmp[2 * BUFSIZE], buf, ret);
		/* __ANNOTATE_LOOP(128) */
		/* memcpy(&tmp[3 * BUFSIZE], buf, ret); */
		/* __ANNOTATE_LOOP(128) */
		/* memcpy(&tmp[4 * BUFSIZE], buf, ret); */
		/* __ANNOTATE_LOOP(128) */
		/* memcpy(&tmp[5 * BUFSIZE], buf, ret); */
		/* __ANNOTATE_LOOP(128) */
		/* memcpy(&tmp[6 * BUFSIZE], buf, ret); */
		/* __ANNOTATE_LOOP(128) */
		/* memcpy(&tmp[7 * BUFSIZE], buf, ret); */
		sendto(fd, tmp, ret, 0, (struct sockaddr *)&addr, addr_len);
	}
	return 0;
}


