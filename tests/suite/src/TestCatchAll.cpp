#include "common.h"

TEST int catch_all(int x) {
    try {
        return may_throw(x);
    } catch (...) {
        log_line("something");
        return -3;
    }
}

TEST int catch_type_then_all(int x) {
    try {
        return may_throw(x);
    } catch (int v) {
        return v;
    } catch (...) {
        return -3;
    }
}
