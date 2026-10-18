// A polymorphic base without a vtable in the image, with data members, as the second base (bncpp-58/59; SynthV's
// dnni::vwWWw at vmi offset 0x40): at -O2 nothing constructs Sink directly, so its vtable is stripped and Logger's
// vmi base list anchors it at +0x18. Its fields come from Logger's code (lifted into Sink), and once Logger's
// struct has Sink as a base, BN reports them for Sink as well: the drop rule for a polymorphic anchored base threw
// them away again every round (cpp/rtti_fields.py, 6d36f41). Like TestNoVtableBase: no common.h helpers.
#define TEST extern "C++" __attribute__((noinline, visibility("default")))

struct Head {  // primary base: Logger's primary vtable serves it
    virtual ~Head() {}
    virtual int id() const = 0;
    long a = 1;
    long b = 2;
};
struct Sink {  // abstract, data members, only ever the second base: anchored at +0x18, no vtable at -O2
    virtual ~Sink() {}
    virtual void put(int v) = 0;
    int count = 0;
    int last = -1;
    long total = 0;
};
struct Logger : Head, Sink {  // size 0x30 from new
    int id() const override { return 7; }
    void put(int v) override {
        count++;
        last = v;
        total += v;
    }
};

TEST Head *make_logger() { return new Logger; }

// the fields through a Logger* at +0x20 / +0x24 / +0x28, i.e. Sink's +0x8 / +0xc / +0x10
TEST long logger_state(Logger *l) { return l->total + l->count * 100 + l->last; }
