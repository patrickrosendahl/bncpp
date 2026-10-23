// Throw sites behind helpers (bncpp-92): vector::at and string::substr throw std::out_of_range through libc++'s
// __throw_out_of_range helpers, fail() is the program's own wrapper around a throw. A call to any of them is a throw
// site with a known type, so the exception path from at_index / tail_of / checked knows what it carries:
// guarded_at catches it (std::out_of_range), guarded_tail through a base (std::logic_error), guarded_checked
// (std::runtime_error); guarded_wrong's catch (std::range_error) does not take it. No common.h helpers.
#include <stdexcept>
#include <string>
#include <vector>
#define TEST extern "C++" __attribute__((noinline, visibility("default")))

TEST int at_index(const std::vector<int> &v, unsigned long i) {
    return v.at(i);
}

TEST int guarded_at(const std::vector<int> &v, unsigned long i) {
    try {
        return at_index(v, i);
    } catch (const std::out_of_range &) {
        return -1;
    }
}

TEST unsigned long tail_of(const std::string &s, unsigned long p) {
    return s.substr(p).size();
}

TEST unsigned long guarded_tail(const std::string &s, unsigned long p) {
    try {
        return tail_of(s, p);
    } catch (const std::logic_error &) {
        return 0;
    }
}

TEST __attribute__((noreturn)) void fail(int code) {
    throw std::runtime_error(code < -100 ? "far below" : "below");
}

TEST int checked(int x) {
    if (x < 0)
        fail(x);
    return x * 3;
}

TEST int guarded_checked(int x) {
    try {
        return checked(x);
    } catch (const std::runtime_error &) {
        return 0;
    }
}

TEST int guarded_wrong(int x) {
    try {
        return checked(x);
    } catch (const std::range_error &) {
        return 1;
    }
}
