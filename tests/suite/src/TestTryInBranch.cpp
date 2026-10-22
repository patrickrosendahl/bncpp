#include "common.h"

// try blocks inside one branch of an if / else and inside one switch case, with code after them in the same
// branch that needs the handler's result (bncpp-67)

TEST int try_in_if(int x) {
    int r = 0;
    if (x > 5) {
        try {
            r = may_throw(x);
        } catch (const std::runtime_error &) {
            r = -1;
        }
        log_line("after try");
    } else {
        r = next_value();
    }
    return r * 2;
}

TEST int try_in_else(int x) {
    int r;
    if (x < 0) {
        r = next_value();
    } else {
        try {
            r = may_throw(x);
        } catch (...) {
            r = -2;
        }
        log_line("else done");
    }
    return r + 1;
}

TEST int try_in_switch(int x) {
    int r;
    switch (x) {
    case 1:
        r = next_value();
        break;
    case 2:
        try {
            r = may_throw(x);
        } catch (int v) {
            r = v;
        }
        log_line("case 2");
        break;
    case 3:
        r = may_throw(3) + 1;
        break;
    case 4:
        r = next_value() * 4;
        break;
    default:
        r = 0;
    }
    return r + 7;
}
