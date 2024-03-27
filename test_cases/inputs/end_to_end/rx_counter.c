#include <stdlib.h>
#include <sys/socket.h>

struct record {
	long long int count;
	long long int bytes;
};

struct record stat;
void loop(int fd) {
	char buf[1024];
	int sz = recvfrom(fd, buf, 1024, 0, NULL, NULL);
	stat.count += 1;
	stat.bytes += sz;
}
