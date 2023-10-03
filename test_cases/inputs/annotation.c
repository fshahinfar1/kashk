#include <stdio.h>
struct __annotation { char *message; };
#define ANNOATE(msg) (struct __annotation){ .message = msg };

int main(int argc, char *argv[])
{
	ANNOATE("hello")
	int a = 2;
	int b = 3;
	return a + b;
}
