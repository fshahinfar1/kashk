#include <stdio.h>

struct record {
	int (*fn)(int, int);
};

int add(int a, int b)
{
	return a + b;
}

int mul(int a, int b)
{
	return a * b;
}

int main(int argc, char *argv[])
{
	/* The goal is to understand how the tool cope with the function
	 * pointer the program.
	 * */
	int x = 10;
	int y = 20;
	int res = 0;
	struct record r;
	r.fn = mul;
	res = r.fn(x, y);
	printf("res: %d\n", res);
	return 0;
}
