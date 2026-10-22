#include "common.h"

TEST int cleanup_and_catch(int x) {
    Guard outer("outer");
    try {
        Guard inner("inner");
        return may_throw(x);
    } catch (const std::runtime_error &e) {
        std::printf("caught %s\n", e.what());
        return -4;
    }
}

// the try block's local is destroyed on unwinding before the catch dispatch: printed once, before the catch list
// (bncpp-65), not inside the catch body
TEST int cleanup_before_dispatch(int x) {
    try {
        Guard inner("inner");
        log_line("in");
        return may_throw(x);
    } catch (int v) {
        return v;
    }
}
