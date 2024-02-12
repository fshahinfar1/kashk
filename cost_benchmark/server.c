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

#define ECHO_MODE 1

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
static int client = 0;
static volatile int running = 0;
void interrupt_handler(int sig)
{
	running = 0;
	if (sock)
		shutdown(sock, SHUT_RDWR);
	if (client)
		shutdown(sock, SHUT_RDWR);
}

int do_udp()
{
	double avg_cross_time = 0;
	size_t count = 0;
	uint64_t acc = 0;
	struct sockaddr_in sk_addr;
	inet_pton(AF_INET, "192.168.1.1", &(sk_addr.sin_addr));
	sk_addr.sin_port = htons(8080);
	sk_addr.sin_family = AF_INET;
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr));
	running = 1;
	signal(SIGINT, interrupt_handler);
#ifdef ECHO_MODE
	printf("The server is running in echo mode\n");
#else
	printf("The server will drop requests\n");
#endif
	printf("Hit Ctrl+C to terminate ...\n");
	while (running) {
		struct sockaddr_in addr;
		socklen_t addr_len = sizeof(addr);
		int ret;
		int size;
		uint64_t user_ts, bpf_ts, travel_time;
		char buf[BUFSIZE];
		size = recvfrom(sock, buf, BUFSIZE, 0,
				(struct sockaddr *)&addr, &addr_len);
		if (size < 1) {
			continue;
		}
		buf[size] = '\0';
		/* printf("recv something: %s\n", buf); */
		/* char *ip = strdup(inet_ntoa(addr.sin_addr)); */
		/* char *tm = strdup(inet_ntoa(sk_addr.sin_addr)); */
		/* printf("%s --> %s\n", tm, ip); */
#ifdef ECHO_MODE
		user_ts = get_ns();
		bpf_ts = ((uint64_t *)buf)[1];
		/* printf("bpf: %ld   user: %ld\n", bpf_ts, user_ts); */
		travel_time = user_ts - bpf_ts;
		count++;
		acc += travel_time;

		ret = sendto(sock, buf, size, 0,
				(struct sockaddr *)&addr, addr_len);
		if (ret <= 0) {
			perror("Failed to echo the message\n");
			continue;
		}
		continue;
#else
		user_ts = get_ns();
		bpf_ts = *(uint64_t *)buf;
		/* printf("bpf: %ld   user: %ld\n", bpf_ts, user_ts); */
		travel_time = user_ts - bpf_ts;
		count++;
		acc += travel_time;
		continue;
#endif
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

int do_tcp()
{
	double avg_cross_time = 0;
	size_t count = 0;
	uint64_t acc = 0;
	struct sockaddr_in sk_addr;
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	inet_pton(AF_INET, "192.168.1.1", &(sk_addr.sin_addr));
	sk_addr.sin_port = htons(8080);
	sk_addr.sin_family = AF_INET;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr));
	running = 1;
	signal(SIGINT, interrupt_handler);

	listen(sock, 1);
	client = accept(sock, (struct sockaddr *)&addr, &addr_len);

#ifdef ECHO_MODE
	printf("The server is running in echo mode\n");
#else
	printf("The server will drop requests\n");
#endif
	printf("Hit Ctrl+C to terminate ...\n");
	while (running) {
		int ret;
		int size;
		uint64_t user_ts, bpf_ts, travel_time;
		char buf[BUFSIZE];
		size = recv(client, buf, BUFSIZE, 0);
		if (size < 1) {
			/* We are handling only one connection */
			running = 0;
			continue;
		}
		buf[size] = '\0';
		/* printf("recv something: %s\n", buf); */
		/* char *ip = strdup(inet_ntoa(addr.sin_addr)); */
		/* char *tm = strdup(inet_ntoa(sk_addr.sin_addr)); */
		/* printf("%s --> %s\n", tm, ip); */
#ifdef ECHO_MODE
		user_ts = get_ns();
		bpf_ts = ((uint64_t *)buf)[1];
		/* printf("bpf: %ld   user: %ld\n", bpf_ts, user_ts); */
		travel_time = user_ts - bpf_ts;
		count++;
		acc += travel_time;

		ret = send(client, buf, size, 0);
		if (ret <= 0) {
			perror("Failed to echo the message\n");
			break;
		}
		continue;
#else
		user_ts = get_ns();
		bpf_ts = *(uint64_t *)buf;
		/* printf("bpf: %ld   user: %ld\n", bpf_ts, user_ts); */
		travel_time = user_ts - bpf_ts;
		count++;
		acc += travel_time;
		continue;
#endif
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

int main(int argc, char *argv[])
{
	/* return do_udp(); */
	return do_tcp();
}
