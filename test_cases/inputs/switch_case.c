#include <stdio.h>

enum {
	state_0,
	state_1,
	state_2,
	state_3,
};


int main(int argc, char *argv[])
{
	int c = 123;
	int b = 0;
	switch (c) {
		case 1:
			printf("c = 1\n");
			break;
		case 3:
			printf("c = 3\n");
			if (!b) {
				printf("c = 3 and not b\n");
			}
			break;
		case 4:
			switch (b) {
				case 1:
					printf("b = 1\n");
					break;
				case 2:
					printf("b = 2\n");
					break;
			}
		default:
			printf("hello wrold\n");
	}

	switch (b) {
		/* This fall through was buggy before :) */
		case state_0:
		case state_1:
		case state_2:
		case state_3:
			b += 3;
			break;
		default:
			b = 12;
	}
	return 0;
}
