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
#include <getopt.h>
#include <net/if.h> /* if_nametoindex */

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h> // XDP_FLAGS_*

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>


struct parameters {
	/* Just load BPF programs do not attach */
	char *binary_path;
	int repeat;
	char *progname;
};
static struct parameters args = {};

void usage(void) {
	printf("loader:\n"
		"  --binary    -b   path to binary file\n"
		"  --repeat    -r   [default 1]\n"
		"  --prog-name -n   [default xdp_prog]\n"
		"  --help      -h\n"
	);
}

void parse_args(int argc, char *argv[]) {
	int ret;

	struct option long_opts[] = {
		{"help",      no_argument,       NULL, 'h'},
		{"binary",    required_argument, NULL, 'b'},
		{"repeat",    required_argument, NULL, 'r'},
		{"prog-name", required_argument, NULL, 'p'},
		/* End of option list ------------------- */
		{NULL, 0, NULL, 0},
	};

	/* Default values */
	args.repeat = 1;
	args.progname = "xdp_prog";

	while (1) {
		ret = getopt_long(argc, argv, "hlb:i:", long_opts, NULL);
		if (ret == -1)
			break;
		switch(ret) {
			case 'b':
				args.binary_path = optarg;
				break;
			case 'r':
				args.repeat = atoi(optarg);
				break;
			case 'p':
				args.progname = optarg;
				break;
			case 'h':
				usage();
				exit(0);
				break;
			default:
				usage();
				exit(1);
				break;
		}
	}
}

int main(int argc, char *argv[])
{
	int ret;
	struct bpf_object *bpfobj;
	struct bpf_program *prog;
	int prog_fd;
	struct bpf_test_run_opts test_opts;
	struct xdp_md ctx_in;
	struct xdp_md ctx_out;


	cpu_set_t cpu_cores;
	CPU_ZERO(&cpu_cores);
	CPU_SET(0, &cpu_cores);
	pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpu_cores);

	parse_args(argc, argv);
	printf("BPF binary: %s\n", args.binary_path);
	bpfobj = bpf_object__open_file(args.binary_path, NULL);
	if (!bpfobj) {
		fprintf(stderr, "Failed to open the BPF binary!\n    %s\n",
				args.binary_path);
		return EXIT_FAILURE;
	}

	/* Load the program to the kernel */
	ret = bpf_object__load(bpfobj);
	if (ret != 0) {
		fprintf(stderr, "Failed to load program to the kernel");
		return 1;
	}

	/* Prepare the packet */
	char *reqstr = "set my key req\nhello world is the value\n";
	const size_t payload_size = strlen(reqstr);
	const size_t max_buf = 4096;
	char *pkt = calloc(1, max_buf);
	char *out_pkt = calloc(1, max_buf);
	size_t pkt_size = sizeof(struct ethhdr) + sizeof(struct iphdr)
		+ sizeof(struct udphdr) + payload_size;
	struct ethhdr *eth = (struct ethhdr *)pkt;
	struct iphdr *ip   = (struct iphdr *)(eth + 1);
	struct udphdr *udp = (struct udphdr *)(ip + 1);
	char *payload = (char *)(udp + 1);
	memset(eth->h_source, 0xff, ETH_ALEN);
	memset(eth->h_dest, 0xff, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IP);
	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr)
			+ payload_size);
	ip->id = 0;
	ip->protocol = IPPROTO_UDP;
	ip->check = 0;
	ip->saddr = htonl(0x7F000001);
	ip->daddr = htonl(0x7F000001);
	udp->source = htons(1234);
	udp->dest = htons(8080);
	udp->len = htons(sizeof(struct udphdr) + payload_size);
	udp->check = 0;
	memcpy(payload, reqstr, payload_size);

	/* TEST */
	prog = bpf_object__find_program_by_name(bpfobj, args.progname);
	if (prog == NULL) {
		fprintf(stderr, "Failed to find xdp_prog");
		return 1;
	}
	prog_fd = bpf_program__fd(prog);
	if (prog_fd < 1) {
		fprintf(stderr, "Failed to find the program file descriptor");
		return 1;
	}
	printf("Program fd: %d\n", prog_fd);

	memset(&ctx_in, 0, sizeof(ctx_in));
	memset(&test_opts, 0, sizeof(struct bpf_test_run_opts));
	ctx_in.data_end = pkt_size;

	test_opts.sz = sizeof(struct bpf_test_run_opts);
	test_opts.data_in = pkt;
	test_opts.data_size_in = pkt_size;
	test_opts.data_out = out_pkt;
	test_opts.data_size_out = max_buf;
	/* test_opts.ctx_in = &ctx_in; */
	/* test_opts.ctx_size_in = sizeof(ctx_in); */
	/* test_opts.ctx_out = &ctx_out; */
	/* test_opts.ctx_size_out = sizeof(ctx_out); */
	test_opts.repeat = args.repeat;
	test_opts.flags = 0;
	test_opts.cpu = 0;
	test_opts.batch_size = 0;

	ret = 0;
	ret = bpf_prog_test_run_opts(prog_fd, &test_opts);
	if (ret < 0) {
		perror("something went wrong\n");
	}
	printf("return value: %d\n", test_opts.retval);

	bpf_object__close(bpfobj);

	return 0;
}
