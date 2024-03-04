#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>


char *process(char *b) {
	/* Must add a bound check */
	int x;
	x = b[0];
	/* Returning the BPF context */
	return b;
}

int main(int argc, char *argv[])
{
	struct conn c = {};
	int sockfd = 1;
	while (1) {
		char buf[128];
		char *p = buf;
		/* p will be pointing to the BPF context */
		int size = recv(sockfd, p, 128, 0);
		p = process(p);
		/* Must add a bound check */
		int x = p[0];
	}
	return 0;
}

