#include "common.h"

TEST std::string string_temporary(int x) {
    std::string s = "value ";
    s += std::to_string(may_throw(x));  // std::string destructors on the unwind path
    return s;
}
