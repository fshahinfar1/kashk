#include <stdio.h>

int main(int argc, char *argv[])
{
	__ANNOTATE("hello")
	int a = 2;
	int b = 3;
	return a + b;
}
