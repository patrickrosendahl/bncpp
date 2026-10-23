#include <stdio.h>
__attribute__((noinline)) static int add3(int a, int b, int c) { return a + b * c; }
__attribute__((noinline)) static long sum(long *p, int n) { long s = 0; for (int i = 0; i < n; i++) s += p[i]; return s; }
int main(int argc, char **argv) { long v[4] = {1, 2, 3, argc}; printf("%d %ld\n", add3(argc, 2, 3), sum(v, 4)); return 0; }
