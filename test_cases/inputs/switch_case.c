#include <stdio.h>


int main(int argc, char *argv[])
{
	int c = 123;
	int b = 0;
	switch (c) {
		case 1:
			printf("hello wrold\n");
			break;
		case 3:
			printf("hello world\n");
			if (!b) {
				printf("hello world\n");
			}
			break;
		default:
			printf("hello wrold\n");
	}
	return 0;
}
