#include "common.h"

// Shapes the readability passes (bncpp-9/10/11/12) must leave alone or keep in order (bncpp-90).

int g_state;  // not static: next_value() may read or write it

// `continue` skips the trailing i--: folding it into `while (--i > 0)` would also decrement on that path
TEST int skip_then_count(int i) {
    int n = 0;
    do {
        if (next_value() == 0) continue;
        n++;
        i--;
    } while (i > 0);
    return n;
}

// the initial value is a call that runs before the condition's call: no `c ? a : next_value()`
TEST int init_call_first(int a) {
    int x = next_value();
    if (next_value() > 0) x = a;
    return x;
}

// the initial value reads g_state before the condition's call may write it: no `c ? a : g_state`
TEST int init_read_first(int a) {
    int x = g_state;
    if (next_value() > 0) x = a;
    return x;
}

// the store of g_state++ sits between two calls that may read it: it must stay there
TEST int store_between_calls() {
    int a = next_value();
    g_state++;
    return a + next_value();
}

// a float comparison is never inverted (NaN): a < b ? 0 : 1 is not a >= b
TEST int not_less(float a, float b) { return a < b ? 0 : 1; }

// a bit test is not a boolean: (x & 4) != 0, not x & 4
TEST int has_bit(int x) { return x & 4 ? 1 : 0; }

// a ternary of two calls: only one of them runs
TEST int pick_call(int c) { return c > 0 ? next_value() : next_value() * 2; }
