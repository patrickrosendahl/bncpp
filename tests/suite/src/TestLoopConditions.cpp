#include "common.h"

TEST int count_until(int limit) {
    int n = 0;
    int v;
    while ((v = next_value()) < limit) n++;
    return n;
}

TEST int sum_odd(const int *a, int len) {
    int s = 0;
    for (int i = 0; i < len; i++) {
        if (a[i] % 2 == 0) continue;
        if (a[i] < 0) break;
        s += a[i];
    }
    return s;
}

TEST int do_while(int x) {
    do {
        x = x / 2 + next_value();
    } while (x > 100);
    return x;
}
