#include "common.h"

// The shapes the readability passes leave in a large function (bncpp-103: SynthV's nhv_dddd_proc, 627 temps, of which
// only ~45 have one definition and one use). Rebuilt here from scratch, one per function; what each should become
// is in its comment.

struct Ring {  // a deque-like block map: capacity = blocks * 64 - 1 unless empty
    unsigned long *map_begin, *map_end;
    unsigned long start, size;
    unsigned long *bits;
    int *counts;
};

void grow(Ring *r);

// bncpp-88: the capacity is computed, then the independent end index, then compared -- the capacity may move past
// the end's assignment: `if ((blocks ? (blocks << 6) - 1 : 0) == r->start + r->size)` or both folded
TEST void push_back_check(Ring *r) {
    unsigned long blocks = r->map_end - r->map_begin;
    unsigned long cap = blocks ? blocks * 64 - 1 : 0;
    unsigned long end = r->start + r->size;
    if (cap == end)
        grow(r);
    r->size++;
}

// a compound store's address: `r->bits[i >> 6] |= 1ul << (i & 63)`, not a temporary for i >> 6
TEST void set_bit(Ring *r, unsigned long i) {
    r->bits[i >> 6] |= 1ul << (i & 63);
}

// a counter through a pointer field: `r->counts[k] += 1`, not a temporary for the loaded pointer
TEST void count(Ring *r, unsigned int k) {
    r->counts[k] += 1;
}

// a value used twice is a variable, not a fold candidate: it should get a name from where it comes from
// (`blocks`), not keep the register name
TEST unsigned long spare(Ring *r) {
    unsigned long blocks = r->map_end - r->map_begin;
    if (blocks > 8)
        log_line("big");
    return blocks * 64 - r->size - (blocks ? 1 : 0);
}

// nested loops with an exit from the inner one into the outer one's middle: BN's HLIL leaves gotos where a
// `continue` / `break` of a structured loop would do
TEST int scan(const int *a, int n, int m) {
    int found = 0;
    for (int i = 0; i < n; i++) {
        if (a[i] < 0)
            continue;
        for (int j = 0; j < m; j++) {
            int v = a[(i + j) % n];
            if (v == 7)
                goto next;
            if (v > 100) {
                found += next_value();
                break;
            }
        }
        found++;
    next:
        if (found > 1000)
            return -1;
    }
    return found;
}

// bncpp-196: a long byte-string literal and a bit test, deep enough to wrap -- BN's line formatter wraps Pseudo C's
// already wrapped text again and must not break a token: every literal piece in its quotes, `TEST_BITQ(` whole
TEST int wrapped_tokens(const unsigned long *bits, unsigned long i, int n) {
    int total = 0;
    for (int k = 0; k < n; k++) {
        for (int j = 0; j < k; j++) {
            try {
                char key[48];
                __builtin_memcpy(key, "\x96\xf4\x01\x4b\x69\x38\x1a\x3e\x8a\xb0\x42\x42\xd6\x68\x9d\xa5\x7f\x60\x6d\x4a"
                                      "\x58\x01\x96\xf4\x01\x4b\x69\x38\x1a\x3e\x8a\xb0\x42\x42\xd6\x68\x9d\xa5\x7f\x60"
                                      "\x6d\x4a\x58\x02\x03\x04\x05", 48);
                log_line(key);
                unsigned long b = i + (unsigned long)(k * n + j);
                if (bits[b >> 6] >> (b & 63) & 1 && bits[(b + 0x1234) >> 6] >> ((b + 0x1234) & 63) & 1)
                    total += may_throw(j);
            } catch (const std::exception &e) {
                total -= 1;
            }
        }
    }
    return total;
}
