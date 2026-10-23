#include "common.h"

// A single-use temporary whose use is the next statement folds into it (bncpp-13).

// a call result used once: folds to `return next_value() + arg1;`
TEST int call_once(int x) {
    int v = next_value();
    return v + x;
}

// an arithmetic temporary used once: folds, parenthesised where it needs to be
TEST int arith_once(int a, int b, int c, int d) {
    int t = a + b * c;
    return t - d;
}

// a side effect between the definition and the use: v must NOT fold (log_line runs in between)
TEST int side_effect_between(int x) {
    int v = next_value();
    log_line("between");
    return v + x;
}

// two call results: each folds into the subtraction, left operand first, order kept
TEST int two_calls(int x) {
    int a = next_value();
    int b = next_value();
    return a - b - x;
}

// a temporary read twice does not fold (it would evaluate the call twice)
TEST int used_twice(int x) {
    int v = next_value();
    return v * v + x;
}
