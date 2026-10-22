#include "common.h"

// exceptions of the program's own classes: thrown with a constructor (called at -O0, inlined at -O2: stores into
// the allocated object, bncpp-65), caught by reference -- the handler's object variable gets the clause's class
// (bncpp-28 source 4)

struct AppError {
    int code;
    const char *where;
    AppError(int c, const char *w) : code(c), where(w) {}
    virtual ~AppError() {}
    virtual int severity() const { return code / 10; }
};

struct IoError : AppError {
    int fd;
    explicit IoError(int f) : AppError(5, "io"), fd(f) {}
    int severity() const override { return 9; }
};

TEST void fail(int x) {
    if (x > 3)
        throw IoError(x);
    if (x > 1)
        throw AppError(x, "app");
    if (x < -5)
        throw 7;
}

TEST int catch_class(int x) {
    try {
        fail(x);
        return 0;
    } catch (IoError &e) {
        return e.fd + e.severity();
    } catch (AppError &e) {
        std::printf("%s\n", e.where);
        return e.code;
    }
}
