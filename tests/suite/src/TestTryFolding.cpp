#include "common.h"

// The readability passes in functions with try regions (bncpp-84): x++ and c ? a : b inside a try block and in a
// catch body, never into, out of or across a try block.

int g_count;  // not static: may_throw() may read or write it

// inside the try block: the post-increment folds, the call stays in the try
TEST int inc_inside(int x) {
    try {
        may_throw(x);
        return g_count++;
    } catch (int) {
        return -1;
    }
}

// a conditional move inside the try block: x = c > 5 ? b : a
TEST int move_inside(int c, int a, int b) {
    try {
        may_throw(c);
        int x = a;
        if (c > 5) x = b;
        return x;
    } catch (int) {
        return 0;
    }
}

// the declaration before the try, its if inside: no ternary across the try
TEST int move_across(int c, int a, int b) {
    int x = a;
    try {
        may_throw(c);
        if (c > 5) x = b;
    } catch (int) {
        log_line("caught");
    }
    return x;
}

// in the catch body: the post-increment folds
TEST int inc_in_catch(int x) {
    try {
        return may_throw(x);
    } catch (int) {
        return g_count++;
    }
}
