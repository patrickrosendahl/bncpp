// The exception path through std::function (bncpp-109): each throwing lambda's operator() has no direct callers
// and no typed receiver -- it is reached through the std::function's __f_. Three ways there, two signatures:
// apply invokes its const& parameter (int(int)), forward passes its parameter on to run_cb (void()), and
// Worker::set moves the function into a member that Worker::work calls later. Like TestVirtual: no common.h.
#include <functional>
#include <stdexcept>
#define TEST extern "C++" __attribute__((noinline, visibility("default")))

TEST int apply(const std::function<int(int)> &f, int x) { return f(x) + 1; }

TEST int guarded_apply(int x) {
    try {
        return apply([x](int y) {
            if (y > 2)
                throw std::runtime_error("big");
            return y + x;
        }, x);
    } catch (std::runtime_error &) {
        return -1;
    }
}

TEST void run_cb(const std::function<void()> &f) { f(); }
TEST void forward(const std::function<void()> &f) { run_cb(f); }

TEST int guarded_forward(int k) {
    try {
        forward([k] {
            if (k)
                throw std::logic_error("k");
        });
    } catch (std::logic_error &) {
        return -1;
    }
    return 0;
}

struct Worker {
    virtual ~Worker();
    std::function<void()> job;
    void set(std::function<void()> f);
    int work();
};
Worker::~Worker() {}
__attribute__((noinline)) void Worker::set(std::function<void()> f) { job = std::move(f); }
__attribute__((noinline)) int Worker::work() {
    try {
        job();
    } catch (std::runtime_error &) {
        return -1;
    }
    return 0;
}

TEST Worker *make_worker() { return new Worker; }

TEST void schedule(Worker *w, int k) {
    w->set([k] {
        if (k > 1)
            throw std::runtime_error("w");
    });
}
