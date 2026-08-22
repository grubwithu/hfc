// Golden fixture: exercises binary if-guards with signed/unsigned
// comparisons, magic numbers, and a length check. Used to verify that
// Functions.ql, Calls.ql, and Guards.ql produce stable, expected facts.
//
// Expected functions: check_signed, check_unsigned, check_magic, check_length, helper, LLVMFuzzerTestOneInput
// Expected direct calls: LLVMFuzzerTestOneInput -> check_signed, check_unsigned, check_magic, check_length
//                         check_* -> helper
// Expected guards: 4 if-guards (one in each check_* function)

#include <stdint.h>
#include <stddef.h>

static int helper(int x) {
    return x + 1;
}

int check_signed(int value) {
    if (value < 0) {
        return helper(-value);
    }
    return helper(value);
}

int check_unsigned(unsigned int value) {
    if (value > 100) {
        return helper((int)value);
    }
    return 0;
}

int check_magic(int value) {
    if (value == 0x42) {
        return helper(value);
    }
    return 0;
}

int check_length(size_t len) {
    if (len > 0 && len < 256) {
        return helper((int)len);
    }
    return -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) return 0;
    int value = *(const int *)(const void *)data;
    check_signed(value);
    check_unsigned((unsigned int)value);
    check_magic(value);
    check_length(size);
    return 0;
}
