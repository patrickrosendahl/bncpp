#include "common.h"

// A function that only returns from its own catch handler (SynthV's license cluster, bncpp-175): every normal path
// ends in a throw, so without exception edges BN infers __noreturn and cuts its callers off after the call.
struct Verdict {
    int code;
};

TEST int verdict_of(int x) {
    try {
        if (x > 5)
            throw Verdict{x * 2};
        log_line("small");
        throw Verdict{may_throw(x)};
    } catch (const Verdict &v) {
        return v.code + 1;
    }
}

TEST int use_verdict(int x) {
    int v = verdict_of(x);
    log_line("after the verdict");  // lost when BN thinks verdict_of never returns
    return v > 3 ? v : -v;
}

// the same with a catch (...) that returns: also a real handler, not a terminate guard
TEST bool check_all(int x) {
    try {
        throw Verdict{x};
    } catch (...) {
        log_line("caught");
        return x > 0;
    }
}

TEST int use_check(int x) {
    if (check_all(x))
        return next_value();
    return 0;
}
