#include <stdio.h>

int main (int argc, char *argv[])
{
	int a = 1;
	int b = 2;
	if (a == 1) {
		a = b;
	} else {
		a = a+b;
	}
	return 0;
}
