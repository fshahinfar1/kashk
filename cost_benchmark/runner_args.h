#ifndef RUNNER_ARGS_H
#define RUNNER_ARGS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <net/if.h>
#include <assert.h>

struct parameters {
	char *binary_path;
	char *input_path;
	size_t repeat;
	char *progname;
	int cross_test;
	char *ifname;
	int ifindex;
};
extern struct parameters args;

void usage(void) {
	printf("loader:\n"
		"  --binary     -b   path to binary file\n"
		"  --input           path to the benchmark input file\n"
		"  --repeat     -r   [default 10^4]\n"
		"  --prog-name  -p   [default prog]\n"
		"  --cross-test -x   run a userspace server for \n"
		"                    testing the kernel/user crossing.\n"
		"  --iface     -i    interface to use in cross test\n"
		"  --help      -h\n"
	);
}

void parse_args(int argc, char *argv[]) {
	int ret;

	struct option long_opts[] = {
		{"help",       no_argument,       NULL, 'h'},
		{"binary",     required_argument, NULL, 'b'},
		{"input",      required_argument, NULL, 128},
		{"repeat",     required_argument, NULL, 'r'},
		{"prog-name",  required_argument, NULL, 'p'},
		{"cross-test", no_argument,       NULL, 'x'},
		{"iface",      required_argument, NULL, 'i'},
		/* End of option list ------------------- */
		{NULL, 0, NULL, 0},
	};

	/* Default values */
	args.repeat = 10000;
	args.progname = "prog";

	while (1) {
		ret = getopt_long(argc, argv, "xhb:i:r:p:", long_opts, NULL);
		if (ret == -1)
			break;
		switch(ret) {
			case 'b':
				args.binary_path = optarg;
				break;
			case 128:
				args.input_path = optarg;
				break;
			case 'r':
				args.repeat = atoi(optarg);
				break;
			case 'p':
				args.progname = optarg;
				break;
			case 'x':
				args.cross_test = 1;
				break;
			case 'i':
				args.ifname = strdup(optarg);
				args.ifindex = if_nametoindex(optarg);
				assert(args.ifindex > 0);
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
#endif
