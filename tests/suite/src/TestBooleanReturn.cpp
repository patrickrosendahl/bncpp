#include "common.h"

TEST bool is_small(int v) {
    if (v > 10) {
        return false;
    }
    return true;
}

TEST bool in_range(int v, int lo, int hi) { return v >= lo && v <= hi; }
