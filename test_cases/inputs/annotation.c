#include <stdio.h>

int main(int argc, char *argv[])
{
	__ANNOTATE("hello", ANN_SKIP)
	int a = 2;
	int b = 3;
	return a + b;
}
