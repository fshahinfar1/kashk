/*
 * This program relies on the BPF_PROG_TEST_RUN.
 * */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <sched.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <net/if.h> /* if_nametoindex */
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "runner_args.h"
#include "runner_global_context.h"
#include "rdtsc.h"
#include "bpf_stats.h"
#include "user_server.h"
#include "shared_map.h"
#include "bpf_loader_helpers.h"

struct parameters args = {};
struct program_context context = {};

#define PAYLOAD_SIZE_MIN 16
#define PAYLOAD_SIZE_LIMIT 4000
#define MAX_BUF 4096
#define DATA_OFFSET (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
		sizeof(struct udphdr))

char *read_payload(void)
{
	if (args.payload_size < PAYLOAD_SIZE_MIN) {
		fprintf(stderr, "Requested payload size is too small (min: %d)\n", PAYLOAD_SIZE_MIN);
		exit(EXIT_FAILURE);
	}
	if (args.payload_size > PAYLOAD_SIZE_LIMIT) {
		fprintf(stderr, "Requested payload size is too large (limit: %d)\n", PAYLOAD_SIZE_LIMIT);
		exit(EXIT_FAILURE);
	}
	char *buf = calloc(1, MAX_BUF);
	int fd = open(args.input_path, O_RDONLY);
	if (fd < 1) {
		perror("Failed to open input file");
		exit(EXIT_FAILURE);
	}
	int size = read(fd, buf, MAX_BUF);
	if (size >= MAX_BUF) {
		fprintf(stderr, "Input file is larger than buffer!\n");
		size = 4095;
	}
	buf[size] = '\0';
	close(fd);
	if (size < args.payload_size) {
		fprintf(stderr, "Requested payload size is larger than input file content\n");
		exit(EXIT_FAILURE);
	}
	/* Truncate the payload string to the size specified by user */
	buf[args.payload_size] = '\0';
	return buf;
}

int run_test(void)
{
	/* double tmp_ns; */
	int ret;
	/* struct fd_info info = {}; */
	char *payload = read_payload();
	char *output = calloc(1, MAX_BUF);
	ret = send_payload(context.prog_fd, payload, output, MAX_BUF);
	/* bpf_read_fdinfo(context.prog_fd, &info); */
	printf("benchmark res: %f\n", context.last_test_duration);
	/* tmp_ns = (double)info.run_time_ns / (double)info.run_cnt; */
	/* printf("benchmark res: %f\n", tmp_ns); */
	printf("return value: %d\n", ret);
	if (ret == XDP_DROP) {
		printf("XDP_DROP\n");
	} else if (ret == XDP_PASS) {
		printf("XDP_PASS\n");
		/* int *failure_number = (int *)(out_pkt + DATA_OFFSET); */
		/* printf("failure number: %d\n", *failure_number); */
	} else {
		printf("XDP_TX\n");
		/* char *resp = output; */
		/* resp += DATA_OFFSET; */
		/* printf("Response:\n%s\n", resp); */
	}
	free(output);
	return ret;
}

struct xdp_config {
	int ifindex;
};


int run_cross_test()
{
	int ret;
	char *payload = read_payload();
	char *output = calloc(1, MAX_BUF);

	/* const int key = 0; */
	/* struct bpf_map *m; */
	/* struct xdp_config cfg = { .ifindex = args.ifindex, }; */
	/* m = bpf_object__find_map_by_name(context.bpfobj, "a_map"); */
	/* bpf_map__update_elem(m, &key, sizeof(key), &cfg, sizeof(cfg), BPF_ANY); */

	ret = 0;
	attach_xdp_program();
	ret = launch_server();
	context.server_pid = ret;
	const size_t repeat = 10000;
	ret = _send_payload(context.prog_fd, payload, output, MAX_BUF, repeat);
	kill(context.server_pid, SIGINT);
	detach_xdp_program();
	sleep(3);
	/* TODO: get the output of the server program */
	return 0;
}

static volatile int running = 1;
int run_xdp()
{
	attach_xdp_program();
	running = 1;
	while (running) {
		sleep(3);
	}
	detach_xdp_program();
	return 0;
}

void interrupt_handler(int sig)
{
	if (context.server_pid != 0) {
		kill(context.server_pid, SIGINT);
		sleep(3);
	}
	if (args.ifindex != 0)
		detach_xdp_program();
	running = 0;
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	cpu_set_t cpu_cores;
	CPU_ZERO(&cpu_cores);
	CPU_SET(2, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);
	parse_args(argc, argv);
	if (args.cross_test == 1) {
		context.live = 1;
	}
	printf("BPF binary: %s\n", args.binary_path);
	load_bpf_binary_and_get_program();
	printf("Program fd: %d\n", context.prog_fd);
	signal(SIGINT, interrupt_handler);
	if (args.cross_test == 1) {
		run_cross_test();
	} else if (args.xdp == 1) {
		run_xdp();
	}else {
		run_test();
	}
	bpf_object__close(context.bpfobj);
	return 0;
}
