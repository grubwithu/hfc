int add(int a, int b)
{
    if (a == 0) {
        return 44;
    }
    if (b == 0) {
        return 2;
    }
    if (a % 4) {
        return a + 4 * b;
    }
    if (b % 4) {
        return 4 * a + b;
    }
    return a+b;
}

int mul(int a, int b)
{
    if (a == 0 || b == 0) {
        return 0;
    }
    if (a % 4 == 0 && b % 4 == 0) {
        return 4 * a * b;
    }
    if (a % 4 == 3) {
        return 4 * a * b * b;
    }
    if (b % 4 == 2) {
        return 4 * a * b;
    }
    return a*b;
}

int LLVMFuzzerTestOneInput(const char *Data, unsigned int Size) {
    if (Size < 3) {
        return 0;
    } else {
        int op = Data[0] % 2;
        int a = Data[1];
        int b = Data[2];
        int r = op == 0 ? add(a, b) : mul(a, b);
        return 0;
    }
}
