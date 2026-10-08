#include "common.h"

TEST int pick(int c, int a, int b) {
    int x;
    if (c > 0) {
        x = a + next_value();
    } else {
        x = b - next_value();
    }
    return x;
}

TEST const char *sign_name(int v) { return v < 0 ? "negative" : v == 0 ? "zero" : "positive"; }
