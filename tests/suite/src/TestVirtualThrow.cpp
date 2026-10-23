// The exception path through virtual calls (bncpp-66): Job::run throws and has no direct callers -- Task::guarded
// calls it through this->vptr (typed 'Task* this' by the class pipeline) and catches std::runtime_error;
// Task::unguarded lets it through to its own direct caller drive(), which catches (...). Sibling Idle::run is
// reached through the same slot but never throws. Like TestVirtual: no common.h helpers.
#include <stdexcept>
#define TEST extern "C++" __attribute__((noinline, visibility("default")))

struct Task {
    virtual ~Task() {}
    virtual int run(int x) = 0;
    virtual int guarded(int x);
    virtual int unguarded(int x);
};
struct Job : Task {
    int run(int x) override;
};
struct Idle : Task {
    int run(int x) override { return x; }
};

int Job::run(int x) {
    if (x > 2)
        throw std::runtime_error("too big");
    return x * 2;
}

int Task::guarded(int x) {
    try {
        return run(x) + 1;
    } catch (std::runtime_error &) {
        return -1;
    }
}

int Task::unguarded(int x) {
    return run(x) + 2;
}

TEST Task *make_task(int k) {
    if (k)
        return new Job;
    return new Idle;
}

TEST int drive(Task *t, int x) {
    try {
        return t->unguarded(x);
    } catch (...) {
        return -2;
    }
}
