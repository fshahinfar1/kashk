#include <stdio.h>

void func(int a, int b);

int impl(int a, int b)
{
	a = a + b;
	return b;
}

int main (int argc, char *argv[])
{
	int a = 1;
	int b = 2;

	func(a, b);

	if (a == 1)
		a = b;

	if (a == 2) {
		a = b;
	} else {
		a = a+b;
	}

	for (int i = 0; i < 10; i++) {
		a *= a;
	}

	b = impl(a, b);

	return 0;
}
