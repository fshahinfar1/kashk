int f1() {
  return 0;
}

int main()
{
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
  return 0;
}
