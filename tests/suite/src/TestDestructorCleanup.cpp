#include "common.h"

TEST int cleanup_only(int x) {
    Guard g("cleanup_only");
    return may_throw(x);
}

TEST int two_guards(int x) {
    Guard a("a");
    int r = may_throw(x);
    Guard b("b");
    return r + may_throw(r);
}
