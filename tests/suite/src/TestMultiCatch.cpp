#include "common.h"

TEST int catch_two_types(int x) {
    try {
        return may_throw(x);
    } catch (const std::runtime_error &e) {
        std::printf("runtime_error: %s\n", e.what());
        return -1;
    } catch (int v) {
        std::printf("int: %d\n", v);
        return -2;
    }
}

TEST int catch_base_and_derived(int x) {
    try {
        return may_throw(x);
    } catch (const std::invalid_argument &e) {
        log_line(e.what());
        return -1;
    } catch (const std::exception &e) {
        log_line(e.what());
        return -2;
    }
}
