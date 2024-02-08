#ifndef USER_SERVER_H
#define USER_SERVER_H
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int launch_server(void)
{
	int ret;
	ret = fork();
	if (ret < 0) {
		fprintf(stderr, "Failed to launch the server program (fork failed)\n");
		exit(EXIT_FAILURE);
	}
	if (ret == 0) {
		/* Child process */
		char *server_binary = "./build/server";
		execl(server_binary, server_binary, (char *)NULL);
		fprintf(stderr, "Failed to launch the server program (exec failed)\n");
		exit(EXIT_FAILURE);
	}
	return ret;
}
#endif
