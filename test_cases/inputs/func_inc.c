#include <stdio.h>

#include "func_inc_header.h"

int func(int a, int b);
int main(int argc, char *argv[])
{
	int ret;
	ret = func(1, 5);
	printf("ret = %d\n", ret);
	return 0;
}

