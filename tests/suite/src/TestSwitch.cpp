#include "common.h"

TEST const char *day_kind(int d) {
    switch (d) {
    case 0:
    case 6:
        return "weekend";
    case 1: case 2: case 3: case 4: case 5:
        return "weekday";
    default:
        return "?";
    }
}

TEST int sparse(int v) {
    switch (v) {
    case 1: return 10;
    case 100: return 20;
    case 1000: log_line("big"); return 30;
    }
    return 0;
}
