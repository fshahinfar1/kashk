int f1() {
  return 0;
}

int main()
{
  int test = f1();
  switch (f1()) {
    case 1:
      break;
    case 2:
      break;
    default:
      break;
  }
  return 0;
}
