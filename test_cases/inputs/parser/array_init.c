#define SIZE 2

int main() {
	char a1[4] = "123";
	char a2[] = "abc";
	char *a3[] = {"123", "456", "789"};
	char __attribute__((aligned(32)))  a4[] = "hello";
	static const char __attribute__((aligned(16)))  a5[16] = "\000\040\177\177";
	char a6[SIZE + 3];
	char a7[SIZE + 3] = "abcd";

	int b1[] = {1,2,3,4,5,6,-1,-1};
	int b2[10] = {};
	int b3[10] = {5,4,};
	return 0;
}
