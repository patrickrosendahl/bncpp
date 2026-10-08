#include "common.h"

TEST int rethrow(int x) {
    try {
        return may_throw(x);
    } catch (const std::exception &e) {
        std::printf("rethrowing %s\n", e.what());
        throw;
    }
}

TEST int throw_other(int x) {
    try {
        return may_throw(x);
    } catch (int v) {
        throw std::runtime_error("int " + std::to_string(v));
    }
}
