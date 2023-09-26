#include <stdio.h>
#include <assert.h>
#include <errno.h>

int main(int argc, char *argv[]) {
	int a = 1;
	int b = 2;
	a = 3;
	b = a;
	if (a == b) {
		printf("hello world\n");
	}
	if (a == b && a > 3) {
		printf("hello world\n");
	}
	if (a == b || a > 3) {
		printf("hello world\n");
	}
	if (a == b && (a > 3 || b < 2)) {
		printf("hello world\n");
	}
	if (a == b && a > 3 || b < 2) {
		printf("hello world\n");
	}
	if (errno == 0) {
		printf("hello world\n");
	}
	assert(a != 1);;
	b *= 5;
	return 0;
}
