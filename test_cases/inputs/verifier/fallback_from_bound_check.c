#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>

#define PORT 8080
#define LISTEN_ADDR "127.0.0.1"

int main() {
	int sock;
	struct sockaddr_in addr;
	socklen_t addr_size;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);
	inet_pton(AF_INET, LISTEN_ADDR, &addr.sin_addr);
	addr_size = sizeof(addr);
	bind(sock, &addr, addr_size);

	while(1) {
		char buf[128];
		int size;
		size = read(sock, buf, 127);
		buf[size] = '\0';
	}
	return 0;
}
