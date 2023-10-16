int func1(int a, int b) {
	/* This is the body of the other function */
	int c = 0;
	while (a < b) {
		a *= a;
		c++;
	}
	return c;
}
