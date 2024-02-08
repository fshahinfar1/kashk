#ifndef RUNNER_ARGS_H
#define RUNNER_ARGS_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

struct parameters {
	char *binary_path;
	char *input_path;
	size_t repeat;
	char *progname;
};
extern struct parameters args;

void usage(void) {
	printf("loader:\n"
		"  --binary    -b   path to binary file\n"
		"  --input     -i   path to the benchmark input file\n"
		"  --repeat    -r   [default 10^7]\n"
		"  --prog-name -p   [default prog]\n"
		"  --help      -h\n"
	);
}

void parse_args(int argc, char *argv[]) {
	int ret;

	struct option long_opts[] = {
		{"help",      no_argument,       NULL, 'h'},
		{"binary",    required_argument, NULL, 'b'},
		{"input",     required_argument, NULL, 'i'},
		{"repeat",    required_argument, NULL, 'r'},
		{"prog-name", required_argument, NULL, 'p'},
		/* End of option list ------------------- */
		{NULL, 0, NULL, 0},
	};

	/* Default values */
	args.repeat = 10000000;
	args.progname = "prog";

	while (1) {
		ret = getopt_long(argc, argv, "hb:i:r:p:", long_opts, NULL);
		if (ret == -1)
			break;
		switch(ret) {
			case 'b':
				args.binary_path = optarg;
				break;
			case 'i':
				args.input_path = optarg;
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
#endif
