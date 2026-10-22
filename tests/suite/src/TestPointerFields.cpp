// Fields that hold object pointers (bncpp-34): typed 'Y*' from what is stored into them. An object from operator
// new (Engine), the constructing object's own 'this' (Child::parent), objects of two sibling classes (Owner::shape:
// their common base Shape), a field copied from another typed field (Owner::spare, the fixpoint), and unrelated
// classes stored into one field (Slot::any: a contradiction, left alone). A constructor parameter stored into a
// field (Block::eng, bncpp-28): the parameter's class from the arguments at its direct callers, through the derived
// constructor's own parameter (void*: the demangled names would type it otherwise). A field stored from a function's
// result (Station::eng, bncpp-28): the class from the callee's return statements, through a wrapper returning another
// callee's result (void* returns: Itanium names carry no return type). A virtual setter's parameter stored into a
// field (Dock::eng, bncpp-28 source 2): the class from the arguments at the virtual calls of its slot, for the
// override (Harbor::attach) too.
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
struct Block {
    Engine *eng;
    Block(void *e) : eng(static_cast<Engine *>(e)) {}
    virtual ~Block() {}
    virtual long go() { return eng->tick(); }
};
struct FastBlock : Block {
    long boost = 2;
    FastBlock(void *e) : Block(e) {}
    long go() override { return boost * eng->tick(); }
};

TEST void *make_engine_raw();
TEST void *engine_again();
struct Station {
    Engine *eng;
    long load = 0;
    Station() : eng(static_cast<Engine *>(engine_again())) {}
    virtual ~Station() {}
    virtual long go() { return load + eng->tick(); }
};

struct Dock {
    Engine *eng = nullptr;
    virtual ~Dock() {}
    virtual void attach(void *e) { eng = static_cast<Engine *>(e); }
    virtual void refit() { attach(new Engine); }
};
struct Harbor : Dock {
    long berths = 3;
    void attach(void *e) override {
        berths += 1;
        eng = static_cast<Engine *>(e);
    }
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
TEST Block *make_block() { return new FastBlock(new Engine); }
TEST void *make_engine_raw() { return new Engine; }
TEST void *engine_again() { return make_engine_raw(); }
TEST Station *make_station() { return new Station; }
TEST Dock *make_dock(int big) { return big ? new Harbor : new Dock; }
