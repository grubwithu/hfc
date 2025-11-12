int main(int argc, char **argv ) {
  char *str = argv[1];
  int size = 0;
  while (str[size]) {
    size++;
  }
  LLVMFuzzerTestOneInput(str, size);
}

