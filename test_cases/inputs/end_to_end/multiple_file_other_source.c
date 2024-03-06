int func1(int a, int b) {
	/* This is the body of the other function */
	int c = 0;
	__ANNOTATE_LOOP(128)
	while (a < b) {
		a *= a;
		c++;
	}
	return c;
}
