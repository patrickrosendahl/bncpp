/* Offline fixture for the sloppy line matcher (bncpp-36): several functions, assert anchors with __FILE__ +
 * __LINE__, string and constant anchors, a call. Built -g (truth) and stripped (input) by ref_line_match.py. */
#include <stdint.h>
#define REQUIRE(e) ((e) ? (void)0 : fail_at("%s:%d " #e, __FILE__, __LINE__))
void fail_at(const char *m, const char *f, int l);
int sink(int x);

int accumulate(int *a, int n)
{
    int total = 0;
    REQUIRE(a != 0);
    for (int i = 0; i < n; i++)
        total += a[i] * 7;
    if (total > 4242)
        total = sink(total);
    return total;
}

int classify(int v)
{
    REQUIRE(v >= 0);
    if (v < 100)
        return 1;
    if (v < 100000)
        return 2;
    return 3;
}

long mix(long seed)
{
    long h = seed ^ 0x9e3779b97f4a7c15L;
    h *= 0xff51afd7ed558ccdL;
    h ^= h >> 33;
    REQUIRE(h != 0);
    return sink((int)h) + 88005553535L;
}
