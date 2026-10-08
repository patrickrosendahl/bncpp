#include "common.h"

TEST int may_throw(int x) {
    if (x > 2) throw std::runtime_error("too big");
    if (x < 0) throw x;
    return x * 2;
}

TEST void log_line(const char *s) { std::puts(s); }

TEST int next_value() { static int n; return ++n; }

Guard::Guard(const char *n) : name(n) { std::printf("enter %s\n", name); }
Guard::~Guard() { std::printf("leave %s\n", name); }

TEST int catch_by_type(int x) {
    try {
        return may_throw(x);
    } catch (const std::runtime_error &e) {
        std::printf("runtime_error: %s\n", e.what());
        return -1;
    }
}
