// Fields that hold object pointers (bncpp-34): typed 'Y*' from what is stored into them. An object from operator
// new (Engine), the constructing object's own 'this' (Child::parent), objects of two sibling classes (Owner::shape:
// their common base Shape), a field copied from another typed field (Owner::spare, the fixpoint), and unrelated
// classes stored into one field (Slot::any: a contradiction, left alone).
#define TEST extern "C++" __attribute__((noinline, visibility("default")))

struct Owner;
TEST void announce(void *p);

struct Engine {
    long rate = 48000;
    Engine() { announce(this); }
    virtual ~Engine() {}
    virtual long tick() { return rate; }
};
struct Child {
    Owner *parent;
    long id = 0;
    Child(Owner *o) : parent(o) { announce(this); }
    virtual ~Child() {}
    virtual long run();
};
struct Shape {
    virtual ~Shape() {}
    virtual long area() { return 0; }
};
struct Square : Shape {
    long side = 2;
    long area() override { return side * side; }
};
struct Circle : Shape {
    long r = 1;
    long area() override { return 3 * r * r; }
};
struct Owner {
    Engine *engine;
    Child *child;
    Shape *shape = nullptr;
    Engine *spare = nullptr;
    Owner();
    virtual ~Owner() {}
    virtual long step() { return engine->tick() + child->run() + (shape ? shape->area() : 0); }
    virtual void reshape(int round) {
        if (round)
            shape = new Square;
        else
            shape = new Circle;
    }
    virtual void share() { spare = engine; }
    virtual long mix() { return spare ? spare->tick() : 0; }
};
struct Slot {
    void *any = nullptr;
    virtual ~Slot() {}
    virtual void hold_engine() { any = new Engine; }
    virtual void hold_child(Owner *o) { any = new Child(o); }
};

long Child::run() { return id + parent->engine->rate; }
Owner::Owner() {
    engine = new Engine;
    child = new Child(this);
    announce(this);
}

TEST void announce(void *p) { static void *last; last = p; }
TEST Owner *make_owner() { return new Owner; }
TEST Slot *make_slot() { return new Slot; }
