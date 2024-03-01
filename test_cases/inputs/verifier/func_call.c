#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>


char *process(char *b) {
	return b;
}

int main(int argc, char *argv[])
{
	struct conn c = {};
	int sockfd = 1;
	while (1) {
		char buf[128];
		char *p = buf;
		int size = recv(sockfd, p, 128, 0);
		p = process(p);
		int x = p[0];
	}
	return 0;
}

