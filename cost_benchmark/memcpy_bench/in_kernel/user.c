#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "shared_ioctl_header.h"

int main(int argc, char **argv)
{
	int fd, ret;
	lkmc_ioctl_struct arg_struct;

	if (argc < 2) {
		puts("Usage: ./prog <ioctl-file>");
		return EXIT_FAILURE;
	}
	fd = open(argv[1], O_RDONLY);
	if (fd == -1) {
		perror("open");
		return EXIT_FAILURE;
	}
	memset(&arg_struct, 0, sizeof(lkmc_ioctl_struct));
	ret = ioctl(fd, LKMC_IOCTL_RUN_BENCH, &arg_struct);
	if (ret == -1) {
		perror("ioctl command failed");
		return EXIT_FAILURE;
	}

	uint64_t dur = arg_struct.duration;
	double avg_arr = (double)dur / (double)arg_struct.repeat; 
	double avg_memcpy = avg_arr / (double)arg_struct.array_size;
	printf("Benchmark results:\n");
	printf("Total duration = %ld\n", dur);
	printf("Avg. array copy = %f\n", avg_arr);
	printf("Avg. memcpy = %f\n", avg_memcpy);
	printf("ret = %d\n", ret);
	printf("errno = %d\n", errno);
	close(fd);
	return EXIT_SUCCESS;
}
