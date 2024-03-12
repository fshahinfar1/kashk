void fail(void);

/* t parameter is unused */
int func(int x, int t) {
	int z;
	int y = x * x;
	if (y % 2 == 0)
		fail();
	z = y * 3 + x;
	return z;
}

int main() {
	int a = 123;
	a = a * 5;
	a = func(a, 0);
	a = a * a;
	return a;
}
