// A single-inheritance chain whose constructors get inlined into the operator new sites (bncpp-31): each base
// constructor calls out with 'this', so its vptr store must stay, and one new object receives the vptr of every
// class of the chain in turn (SynthV's notegroup_factory). Every class is also allocated on its own: the size of
// a new site belongs only to the most derived class stored into it.
#define TEST extern "C++" __attribute__((noinline, visibility("default")))

struct Worker;
TEST void enlist(Worker *w);

struct Worker {  // root
    int state = 0;
    long queue[4] = {};
    Worker() { enlist(this); }
    virtual ~Worker() {}
    virtual long pump() { return queue[state & 3]; }
};
struct Driver : Worker {
    double rate = 1;
    Driver() { enlist(this); }
    long pump() override { return (long)(rate * Worker::pump()); }
};
struct NoteGroup : Driver {
    long notes[8] = {};
    NoteGroup() { enlist(this); }
    long pump() override { return notes[state & 7] + Driver::pump(); }
};

static Worker *registry[16];
static int registered;

TEST void enlist(Worker *w) {
    registry[registered++ & 15] = w;
    w->state += (int)w->pump();  // a virtual call on the object under construction: the vptr must be set
}

TEST Worker *make_worker() { return new Worker; }
TEST Worker *make_driver() { return new Driver; }
TEST Worker *make_group() { return new NoteGroup; }
