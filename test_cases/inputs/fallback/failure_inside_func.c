void fail(void);

int func(int x) {
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
	a = func(a);
	a = a * a;
	return a;
}
