#include <stdio.h>


int main(int argc, char *argv[])
{
	int c = 123;
	int b = 0;
	switch (c) {
		case 1:
			{
			printf("hello wrold1\n");
			break;
		       }
		case 2:
			c = 2;
			printf("hello world4\n");
			if (!b) {
				printf("hello world5\n");
			}
			break;
		case 3:
			{
			c = 2;
			printf("hello world4\n");
			if (!b) {
				printf("hello world5\n");
			}
			break;
			}
		default:
			printf("hello wrold\n");
	}
	return 0;
}
