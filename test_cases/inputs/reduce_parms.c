#include <stdio.h>

int func(int a, int b, int c, int d, int e, int f, int g, int h, int i)
{
	return a + b + c + d + e + f + g + h + i;
}

int func2(int a, int b, int c, int d, int e, int f, int g, int h, int i)
{
	return a + b + c + d + e + f + g + h + i;
}

int main()
{
	func(1,2,3,4,5,6,7,8,9);
	func2(1,2,3,4,5,6,7,8,9);
	return 0;
}
