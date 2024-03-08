#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#ifndef __ANNOTATE_LOOP
#define __ANNOTATE_LOOP(x)
#endif

pthread_mutex_t m;
int arr[100];

void *fail(int a, int b);

int f1()
{
	pthread_mutex_lock(&m);
	for (int i = 0; i < 100; i++)
		arr[i] = i;
	pthread_mutex_unlock(&m);
	return 0;
}

int f2()
{
	char *str;
	/* should fail here */
	str = fail(1, 256);
	if (str == NULL) {
		return -1;
	}
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
		pthread_mutex_init(&m, NULL);
		f1();
	} else if (b % 5 == 2) {
		b *= 30;
		f2();
	} else if (b % 5 == 3) {
		/* If a function defenately is going to fail then we should not */
		/* investigate the other failuers of this path. (we have failed */
		/* at f1 do not create a new path for the pthread_mutex_init). */
		/* This was a bug :)
		 * */
		f1();
		b = a;
		pthread_mutex_init(&m, NULL);
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
	while(fail(1, 2) != NULL) {
		b = a;
	}

	return 0;
}
