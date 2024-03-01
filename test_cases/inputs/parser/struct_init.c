struct my_type {
	int a;
	int b;
	char *c;
};
int main()
{
	int x = 10;
	struct my_type m = {
		.a = x,
		.b = 20,
		.c = "hello\n",
	};
	return 0;
}
