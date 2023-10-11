#include <stdio.h>

int main(int argc, char *argv[])
{
	int a;
	int i;
	a = 0;
	/* a simple for loop with 4 parts (children in AST graph) */
	for (i = 0; i < 10; i++) {
		a += i;
	}
	printf("1. a = %d\n", a);

	a = 0;
	i = 0;
	/* a simple for loop with 3 parts (children in AST graph) */
	for (; i < 10; i++) {
		a += i;
	}
	printf("2. a = %d\n", a);

	a = 0;
	i = 0;
	/* a simple for loop with 3 parts (children in AST graph) */
	for (i = 0; ; i++) {
		if (i >= 10)
			break;
		a += i;
	}
	printf("3. a = %d\n", a);

	a = 0;
	i = 0;
	/* a simple for loop with 2 parts (children in AST graph) */
	for (i = 0; i < 10;) {
		a += i;
		i++;
	}
	printf("4. a = %d\n", a);

	a = 0;
	i = 0;
	/* a simple for loop with 2 parts (children in AST graph) */
	for (; ; i++) {
		if (i >= 10)
			break;
		a += i;
	}
	printf("5. a = %d\n", a);

	a = 0;
	i = 0;
	/* a simple for loop with 2 parts (children in AST graph) */
	for (; i < 10;) {
		a += i;
		i++;
	}
	printf("6. a = %d\n", a);

	a = 0;
	i = 0;
	/* a simple for loop with 1 parts (children in AST graph) */
	for (; ; ) {
		if (i >= 10)
			break;
		a += i;
		i++;
	}
	printf("7. a = %d\n", a);


	for (;;);

	/* This for loop is testing detection of paranthesis and semicolons */
	for(char*p=strtok_r(list,";,",&b);p!=NULL;p=strtok_r(NULL,";,",&b)){ a++; }

	return 0;
}
