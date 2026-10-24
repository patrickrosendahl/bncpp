// bncpp-101 / bncpp-30: arm64 trap bodies ('brk #0x1') that BN neither ends a function at nor creates functions for.
// An abstract class's destructor that can never run as the most-derived one: clang emits the deleting destructor
// of Base (pure virtual) / an unreachable body as a lone trap, reachable only through the vtable.
struct Base {
    virtual ~Base() = 0;
    virtual int f() = 0;
};
Base::~Base() {}

struct Never final : Base {
    ~Never() override { __builtin_unreachable(); }
    int f() override { __builtin_trap(); }
};

struct Leaf : Base {
    int x;
    explicit Leaf(int v) : x(v) {}
    int f() override { return x; }
};

extern "C" Base* make_never();
Base* make_never() { return nullptr; }  // Never is never constructed here, only its vtable exists
Base* make_leaf(int v) { return new Leaf(v); }
Base* make_never_obj() { return new Never(); }
