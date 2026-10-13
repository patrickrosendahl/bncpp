// Polymorphic classes for the class scan (cpp/rtti.py, bncpp-21): every typeinfo kind, primary and secondary
// vtables, thunks, a pure virtual and a template. No common.h helpers, so the dylib links without
// -undefined dynamic_lookup and also builds with chained fixups (TestVirtualChained).
#include <typeinfo>

#define TEST extern "C++" __attribute__((noinline, visibility("default")))

struct Shape {  // root: __class_type_info
    virtual ~Shape() {}
    virtual double area() const { return 0; }
    virtual const char *kind() const = 0;  // pure virtual: abstract class
};
struct Circle : Shape {  // single inheritance: __si_class_type_info
    double r = 1;
    double area() const override { return 3.14159 * r * r; }
    const char *kind() const override { return "circle"; }
};
struct Named {
    virtual ~Named() {}
    virtual const char *name() const { return "named"; }
};
struct NamedCircle : Circle, Named {  // multiple inheritance: __vmi_class_type_info, a secondary vtable
    const char *name() const override { return "named circle"; }  // + a this-adjusting thunk
};
struct Node {
    virtual ~Node() {}
    virtual int id() const { return 0; }
};
struct Left : virtual Node { int id() const override { return 1; } };    // virtual base: virtual thunks
struct Right : virtual Node { int id() const override { return 2; } };
struct Diamond : Left, Right { int id() const override { return 3; } };  // diamond
template <typename T> struct Box : Shape {  // a template, two instantiations
    T value{};
    double area() const override { return (double)value; }
    const char *kind() const override { return "box"; }
};

TEST Shape *make_shape(int k) {
    switch (k) {
    case 0: return new Circle;
    case 1: return new NamedCircle;
    case 2: return new Box<int>;
    default: return new Box<double>;
    }
}

TEST Node *make_node(int k) {
    if (k == 0) return new Left;
    if (k == 1) return new Right;
    return new Diamond;
}

TEST const char *shape_name(Shape *s) {
    if (Named *n = dynamic_cast<Named *>(s)) return n->name();
    return typeid(*s).name();
}

TEST double total_area(Shape **shapes, int n) {
    double sum = 0;
    for (int i = 0; i < n; i++)
        sum += shapes[i]->area();
    return sum;
}
