#include <iostream>
using namespace::std;
struct s1 {
  int a;
  int b;
};

int f1() {
  return 0;
}

int main()
{
  struct s1 *s;
  s = (struct s1 *)(0xffff);
  int test = f1();
  switch (f1()) {
    case 1:
      if (f1() == 2) {
        return 3;
      }
      break;
    case 2:
      break;
    default:
      break;
  }
  cout << "test is: " << test << " and s->a is: " << s->a << endl;
  return 0;
}
