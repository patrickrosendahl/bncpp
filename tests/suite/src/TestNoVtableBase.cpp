// Bases without a vtable of their own, anchored by the RTTI base lists (bncpp-31, cpp/rtti_fields.py
// anchored_bases): at -O2 the linker strips the vtable of a base nothing constructs directly (Shape below --
// only its typeinfo stays, referenced by Wheel's si base list; like TestVirtual's Shape / Named), and a base
// with no virtual functions never has one (Plain -- Bike's vmi base list still gives its offset). Like
// TestVirtual: no common.h helpers, so the dylib links without -undefined dynamic_lookup.
#define TEST extern "C++" __attribute__((noinline, visibility("default")))

struct Shape {  // root: __class_type_info; at -O2 no vtable in the image
    virtual ~Shape() {}
    virtual double area() const { return 0; }
    virtual const char *kind() const = 0;
};
struct Wheel : Shape {  // single inheritance: __si_class_type_info anchors Shape at offset 0
    double r = 1;
    double area() const override { return 3 * r; }
    const char *kind() const override { return "wheel"; }
};
struct Plain {  // no virtual functions: Bike's vmi base list anchors it at its offset, nothing serves it
    int spokes = 2;
    int tension = 3;
};
struct Bike : Wheel, Plain {  // multiple inheritance: Wheel at 0 (served by the primary vtable), Plain after
    const char *kind() const override { return "bike"; }
};

TEST Shape *make_it(int k) {
    switch (k) {
    case 0:
        return new Wheel;
    default:
        return new Bike;
    }
}

// Plain's fields come from Bike's constructor stores at +0x10 / +0x14 (lifted into Plain); this reads them through
// an untyped Bike* (no evidence of its own)
TEST double spoke_sum(Bike *b) {
    return b->spokes + b->tension;
}
