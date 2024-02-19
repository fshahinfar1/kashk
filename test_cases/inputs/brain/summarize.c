#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>

#define BUFSIZE 128

void not_offloadable_func(int x);
int parse(char *buf, size_t s) {
	int x = 0;
	for (size_t i = 0; i < 256; i++) {
		if (i >= s) break;
		x += buf[i];
	}
	return x;
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
		if (ret < 8)
			continue;
		int x = parse(buf, ret);
		switch (buf[0]) {
			case 'g':
				not_offloadable_func(x);
				break;
			case 's':
				not_offloadable_func(x);
				break;
		}
	}
	return 0;
}
