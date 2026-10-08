#include "common.h"

TEST int nested_try(int x) {
    try {
        try {
            return may_throw(x);
        } catch (int v) {
            std::printf("inner int %d\n", v);
            return may_throw(v + 10);
        }
    } catch (const std::runtime_error &e) {
        std::printf("outer %s\n", e.what());
        return -5;
    }
}

TEST int try_in_loop(int n) {
    int sum = 0;
    for (int i = 0; i < n; i++) {
        try {
            sum += may_throw(i);
        } catch (const std::runtime_error &) {
            sum -= 1;
        }
    }
    return sum;
}
