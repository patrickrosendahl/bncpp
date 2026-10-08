#include "common.h"

static int counter;
static int table[16];

TEST int post_increment() { return counter++; }

TEST int pre_increment() { return ++counter; }

TEST void fill(int v) {
    int i = 0;
    while (i < 16) table[i++] = v;
}
