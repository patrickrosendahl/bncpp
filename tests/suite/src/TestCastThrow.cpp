// The exception path through a call on a dynamic_cast result (bncpp-95): Batch::flush throws and has no direct
// callers; try_flush calls it on dynamic_cast<Batch *>(t), a receiver only the cast types (t is a Work*, so
// nothing else tells BN which class it is) and catches std::logic_error. Spool overrides flush and never throws.
// Like TestVirtual: no common.h helpers.
#include <stdexcept>
#define TEST extern "C++" __attribute__((noinline, visibility("default")))

struct Work {
    virtual ~Work() {}
    virtual int run(int x) = 0;
};
struct Batch : Work {
    int run(int x) override { return x + 1; }
    virtual int flush(int x);
};
struct Spool : Batch {
    int flush(int x) override { return x; }
};

int Batch::flush(int x) {
    if (x < 0)
        throw std::logic_error("negative");
    return x * 3;
}

TEST Work *make_work(int k) {
    if (k > 1)
        return new Spool;
    if (k)
        return new Batch;
    return nullptr;
}

TEST int try_flush(Work *t, int x) {
    try {
        if (Batch *b = dynamic_cast<Batch *>(t))
            return b->flush(x);
        return 0;
    } catch (std::logic_error &) {
        return -3;
    }
}
