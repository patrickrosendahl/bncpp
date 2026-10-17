// Closure targets vs classes (cpp/rtti_closures.py, bncpp-23): lambdas in std::function and in a hand-written
// function object become classes with a vtable; next to them, class families of the same shape that must stay
// classes (a base with its own code, an exception hierarchy, a family too small).
#include <functional>

#define TEST extern "C++" __attribute__((noinline, visibility("default")))

// std::function: each lambda is a std::__function::__func<...> (9 slots, operator() at [6])
TEST std::function<int(int)> add_fn(int k) { return [k](int x) { return x + k; }; }
TEST std::function<int(int)> scale_fn(int a, int b) { return [a, b](int x) { return x * a + b; }; }
TEST std::function<int(int)> pick_fn(const int *table, int n, int dflt) {
    return [table, n, dflt](int x) { return x >= 0 && x < n ? table[x] : dflt; };
}
TEST int call_fn(const std::function<int(int)> &f, int x) { return f(x); }

// a hand-written function object (like SynthV's dnni::function): ~, ~ [deleting], call [2]
struct FnBase {
    virtual ~FnBase() {}
    virtual int call(int x) = 0;
};
template <class F> struct FnImpl : FnBase {
    F f;
    explicit FnImpl(F g) : f(g) {}
    int call(int x) override { return f(x); }
};
template <class F> FnBase *make_fn(F f) { return new FnImpl<F>(f); }
TEST FnBase *neg_obj() { return make_fn([](int x) { return -x; }); }
TEST FnBase *add_obj(int k) { return make_fn([k](int x) { return x + k; }); }
TEST FnBase *clamp_obj(int lo, int hi) { return make_fn([lo, hi](int x) { return x < lo ? lo : x > hi ? hi : x; }); }
TEST int call_obj(FnBase *f, int x) { return f->call(x); }

// counter-example: the base implements its method (its own vtable, not only destructors)
struct Codec {
    virtual ~Codec();
    virtual int run(int x);
};
Codec::~Codec() {}
int Codec::run(int x) { return x; }
struct Rot : Codec { int run(int x) override { return x + 13; } };
struct Inv : Codec { int run(int x) override { return ~x; } };
struct Swap : Codec { int run(int x) override { return (x << 16) | ((unsigned)x >> 16); } };
TEST Codec *make_codec(int k) { return k == 0 ? (Codec *)new Rot : k == 1 ? (Codec *)new Inv : new Swap; }

// counter-example: an exception hierarchy has the 3-slot shape (~, ~ [deleting], what()) but is caught
struct Err {
    virtual ~Err() {}
    virtual const char *what() const = 0;
};
struct IoErr : Err { const char *what() const override { return "io"; } };
struct ParseErr : Err { const char *what() const override { return "parse"; } };
struct RangeErr : Err { const char *what() const override { return "range"; } };
TEST void fail(int k) {
    if (k == 0) throw IoErr();
    if (k == 1) throw ParseErr();
    throw RangeErr();
}
TEST const char *try_fail(int k) {
    try {
        fail(k);
    } catch (const Err &e) {
        return e.what();
    }
    return "none";
}

// counter-example: a single-method interface with only two implementations (below the family minimum)
struct Sink {
    virtual ~Sink() {}
    virtual void put(int x) = 0;
};
struct NullSink : Sink { void put(int) override {} };
struct CountSink : Sink { int n = 0; void put(int) override { ++n; } };
TEST Sink *make_sink(int k) { return k ? (Sink *)new CountSink : new NullSink; }
