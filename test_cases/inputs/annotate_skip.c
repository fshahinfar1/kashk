#include <stdio.h>

void f(void)
{
	printf("hello\n");
}

int main(int argc, char *argv[])
{
	int a = 100;
	int b = 200;
	int c = 300;
	/* void (*cb)(void); */
	/* cb = f; */

	if (a % 3 == 1) {
		__ANNOTATE_SKIP
		a = b * c;
	} else if (a % 3 == 2) {
		a = b + c;
		__ANNOTATE_SKIP
		c = a * 2;
	} else {
		a = 0;
	}

	switch (c) {
		case 1:
			__ANNOTATE_SKIP
			a = b *c;
			break;
		case 2:
			if (c > 0) {
				__ANNOTATE_SKIP
				c *= 3;
			} else {
				__ANNOTATE_FUNC_PTR_IS("cb", "f");
				/* we are not using func ptr. just checking
				 * that other types of annotation does not
				 * cause ToUserspace instructions if not needed
				 * */
				f();
			}
	}
	return 0;
}
