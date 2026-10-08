// Shared by the suite sources: opaque helpers the optimizer cannot see through, so every test keeps its shape.
#pragma once
#include <cstdio>
#include <stdexcept>
#include <string>

#define TEST extern "C++" __attribute__((noinline, visibility("default")))

int may_throw(int x);  // throws std::runtime_error for x > 2, int for x < 0 (TestTryCatch.cpp)
void log_line(const char *s);
int next_value();

struct Guard {  // a destructor that runs during unwinding (cleanup landing pad)
    const char *name;
    explicit Guard(const char *n);
    ~Guard();
};
