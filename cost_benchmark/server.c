#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>

#define BUFSIZE 128

static uint64_t get_ns(void)
{
	int ret;
	uint64_t ns;
	struct timespec tp;
	ret = clock_gettime(CLOCK_MONOTONIC, &tp);
	if (ret != 0) {
		return 0;
	}
	ns = tp.tv_sec * 1000000000 + tp.tv_nsec;
	return ns;
}

static int sock = 0;
static volatile int running = 0;
void interrupt_handler(int sig)
{
	running = 0;
	shutdown(sock, SHUT_RDWR);
}

int main(int argc, char *argv[])
{
	double avg_cross_time = 0;
	size_t count = 0;
	uint64_t acc = 0;
	struct sockaddr_in6 sk_addr, addr;
	socklen_t addr_len;
	/* inet_pton(AF_INET6, "::::", &(sk_addr.sin_addr)); */
	memset(sk_addr.sin6_addr.s6_addr, 0, 16);
	sk_addr.sin6_port = htons(8080);
	sk_addr.sin6_family = AF_INET6;
	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr));
	running = 1;
	signal(SIGINT, interrupt_handler);
	printf("Hit Ctrl+C to terminate ...\n");
	while (running) {
		int ret;
		uint64_t user_ts, bpf_ts, travel_time;
		char buf[BUFSIZE];
		ret = recvfrom(sock, buf, BUFSIZE, 0,
				(struct sockaddr *)&addr, &addr_len);
		if (ret < 1) {
			continue;
		}
		buf[ret] = '\0';
		printf("recv something: %s\n", buf);
		user_ts = get_ns();
		bpf_ts = ((uint64_t *)buf)[0];
		travel_time = user_ts - bpf_ts;
		count++;
		acc += travel_time;
		/* Drop everything */
	}
	if (count == 0) {
		avg_cross_time = 0;
	} else {
		avg_cross_time = (double)acc / (double)count;
	}
	printf("End of experiment\n");
	printf("Received: %ld\n", count);
	printf("Benchmark result: %f\n", avg_cross_time);
	return 0;
}
