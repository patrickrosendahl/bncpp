// Fields reached only through untyped helpers (bncpp-33, after SynthV's tagmap): the constructor passes 'this' to
// a helper taking void* (register_keys), which passes it on to another (insert), which passes the interior pointer
// &buckets to a third (rehash). Only the helpers access bucket_count and elems (at -O2 the constructor zeroes
// buckets..elems with two 16-byte stores, which BN reports as int128 at +0x18 / +0x28), and only insert reads
// max_load as a float (the constructor stores the constant 0x3f800000: an int32 to BN). void* parameters: the
// demangled names would type them otherwise.
#define TEST extern "C++" __attribute__((noinline, visibility("default")))

struct Buckets {
    void **slots;
    unsigned long count;
};

struct TagMap {
    int flags = 0;
    void *ctx;
    void **buckets = nullptr;
    unsigned long bucket_count = 0;
    void *head = nullptr;
    unsigned long elems = 0;
    float max_load = 1.0f;
    TagMap(void *c);
    virtual ~TagMap() { delete[] buckets; }
    virtual int kind() const { return flags; }
};

TEST void rehash(void *bk, unsigned long n) {
    Buckets *b = (Buckets *)bk;
    delete[] b->slots;
    b->slots = new void *[n];
    b->count = n;
    for (unsigned long i = 0; i < n; i++)
        b->slots[i] = nullptr;
}

TEST void insert(void *self, long key) {
    TagMap *m = (TagMap *)self;
    if (m->bucket_count == 0 || (float)(m->elems + 1) > (float)m->bucket_count * m->max_load)
        rehash(&m->buckets, m->bucket_count * 2 + 1);
    m->head = (void *)key;
    m->elems += 1;
}

TEST void register_keys(void *self, long k) {
    insert(self, k);
    insert(self, k + 1);
}

TagMap::TagMap(void *c) : ctx(c) { register_keys(this, 7); }

TEST TagMap *make_tagmap(void *c) {
    return new TagMap(c);
}
