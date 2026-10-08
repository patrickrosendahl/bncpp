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
