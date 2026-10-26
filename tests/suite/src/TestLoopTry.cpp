#include "common.h"

// Loop tests and try ranges (bncpp-147, binary-jvm jvm-101): a loop test that can throw must stay inside the try
// that covers it, and a test outside the try must not be pulled into it.

TEST int while_in_try(int n) {  // the whole loop in the try, the throwing call in its condition
    int s = 0;
    try {
        int i = 0;
        while (may_throw(i) < n) {
            s += i;
            i++;
        }
    } catch (const std::runtime_error &) {
        s = -1;
    }
    return s;
}

TEST int try_in_while(int n) {  // the condition outside the try, the try in the body
    int s = 0;
    while (next_value() < n) {
        try {
            s += may_throw(s);
        } catch (const std::runtime_error &) {
            s -= 1;
        }
    }
    return s;
}

TEST int test_in_try(int n) {  // the loop test inside the try (jvm-101): BN may lift it into the loop header
    int s = 0;
    int i = 0;
    for (;;) {
        try {
            if (may_throw(i) >= n) break;
            s += i;
        } catch (const std::runtime_error &) {
            s -= 1;
        }
        i++;
    }
    return s;
}

TEST int do_test_in_try(int n) {  // do-while: the test at the bottom of the body, inside the try
    int s = 0;
    int i = 0;
    bool more = true;
    do {
        try {
            s += i;
            more = may_throw(i) < n;
        } catch (const std::runtime_error &) {
            s -= 1;
        }
        i++;
    } while (more);
    return s;
}

TEST int do_cond_throws(int n) {  // do-while whose condition throws, the try in the body only
    int s = 0;
    do {
        try {
            s += may_throw(s);
        } catch (const std::runtime_error &) {
            s -= 2;
        }
    } while (may_throw(s) < n);
    return s;
}
