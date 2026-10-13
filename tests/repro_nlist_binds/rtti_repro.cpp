// Minimal repro: polymorphic classes whose RTTI Binary Ninja should recover from a Mach-O executable.
// single inheritance (__si_class_type_info), multiple and virtual inheritance (__vmi_class_type_info),
// a root class (__class_type_info) and a class template.
#include <cstdio>
#include <typeinfo>

struct Shape {
    virtual ~Shape() {}
    virtual double area() const { return 0; }
};
struct Circle : Shape {
    double r = 1;
    double area() const override { return 3.14159 * r * r; }
};
struct Named {
    virtual ~Named() {}
    virtual const char *name() const { return "named"; }
};
struct NamedCircle : Circle, Named {  // multiple inheritance
    const char *name() const override { return "circle"; }
};
struct Node {
    virtual ~Node() {}
    virtual int id() const { return 0; }
};
struct Left : virtual Node { int id() const override { return 1; } };
struct Right : virtual Node { int id() const override { return 2; } };
struct Diamond : Left, Right {  // virtual inheritance
    int id() const override { return 3; }
};
template <typename T> struct Box : Shape {
    T value{};
    double area() const override { return (double)value; }
};

__attribute__((visibility("default"))) Shape *make_shape(int k) {
    switch (k) {
    case 0: return new Circle;
    case 1: return new NamedCircle;
    case 2: return new Box<int>;
    default: return new Box<double>;
    }
}
__attribute__((visibility("default"))) Node *make_node(int k) {
    if (k == 0) return new Left;
    if (k == 1) return new Right;
    return new Diamond;
}
__attribute__((visibility("default"))) const char *shape_kind(Shape *s) {
    if (dynamic_cast<Named *>(s)) return "named";
    return typeid(*s).name();
}

#ifdef REPRO_MAIN
int main(int argc, char **) {
    Shape *s = make_shape(argc);
    Node *n = make_node(argc);
    std::printf("%s %f %d\n", shape_kind(s), s->area(), n->id());
    delete s;
    delete n;
}
#endif
