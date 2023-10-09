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

typedef void(*callback)(int);

void report(int a)
{
	printf("res: %d\n", a);
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
	struct record *r2;
	callback cb;
	void (*cb2)(int);
	r2 = &r;
	r.fn = mul;
	res = r.fn(x, y);
	res = r2->fn(x, y);
	cb = report;
	cb(res);

	/* There was an error recognizing the type of cb2 */
	cb2 = report;
	cb2(res);
	return 0;
}
