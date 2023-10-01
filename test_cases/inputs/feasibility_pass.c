#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

pthread_mutex_t m;
int arr[100];

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
	str = calloc(1, 256);
	if (str == NULL) {
		return -1;
	}
	for (unsigned char i = 0; i < 255; i++)
		str[i] = i;
	return 0;
}

int main(int argc, char *argv[])
{
	int a;
	int b;
	a = 10;
	b = a * a;

	if (b % 3 == 1) {
		/* should fail on this path right here */
		pthread_mutex_init(&m, NULL);
		f1();
	} else if (b % 3 == 2) {
		f2();
	} else {
		int c = a + b;
		/* we ignore prints so this is fine */
		printf("c = %d\n", c);
	}

	return 0;
}
