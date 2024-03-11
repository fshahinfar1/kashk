#include <stdlib.h>
#include <stdio.h>

#ifndef __ANNOTATE_LOOP
#define __ANNOTATE_LOOP(x)
#endif

int arr[100];

void *fail(int a, int b);

int f1()
{
	for (int i = 0; i < 100; i++)
		arr[i] = i;
	return 0;
}

int f2()
{
	char *str;
	str = "1234";
	if (str == NULL) {
		printf("something");
	}
	/* should fail here */
	fail(1, 256);
	for (unsigned char i = 0; i < 255; i++)
		str[i] = i;
	return 0;
}

void f3(char *c)
{
	// The code had a problem when the function did not had any return statements!
	int a = 0;
	int b = 3;
	*c = (a + b) * 30;
}

void f4(int a) {
	/* This function may fail but it can also succeed */
	if (a % 2 == 0) {
		f2();
	} else {
		a = a * 2;
	}
}

int main(int argc, char *argv[])
{
	int a;
	int b;
	char d = 'F';
	a = 10;
	b = a * a;

	if (b % 5 == 1) {
		/* should fail on this path right here */
		fail(1, 2);
		f1();
	} else if (b % 5 == 2) {
		b *= 30;
		f2();
	} else if (b % 5 == 3) {
		/* If a function defenately is going to fail then we should not */
		/* investigate the other failuers of this path. (we have failed */
		/* at fail(0,1) do not create a new path for the fail(3, 4). */
		/* This was a bug :)
		 * */
		fail(0, 1);
		b = a;
		fail(3, 4);
	} else if (b % 5 == 4) {
		f4(b);
	} else {
		int c = a + b;
		/* we ignore prints so this is fine */
		printf("c = %d\n", c);
	}
	f3(&d);

	/* Should handle the fail path before the while */
	__ANNOTATE_LOOP(100)
	while(fail(5, 6) != NULL) {
		b = a;
	}

	return 0;
}
