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

// a noexcept boundary: the call's landing pad is a terminate guard (catch (...) calling clang's helper), no try
TEST int no_throw_boundary(int x) noexcept {
    return may_throw(x) + 1;
}
