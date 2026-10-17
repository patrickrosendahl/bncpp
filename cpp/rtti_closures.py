"""Closure targets among the classes cpp/rtti.py recovered (bncpp-23): std::function-style function objects.

A lambda stored in a std::function (or a home-made one such as SynthV's dnni::function) becomes a class of its
own, derived from the function wrapper's abstract base, with a vtable whose call-operator slot is the lambda's
body. They look like classes, but calls through them are callback hops, not virtual dispatch on an object
model; class recovery and call-graph walks need to tell them apart.

The tell is the family, not the class: the wrapper's base B
  - is a root (no bases of its own) with no vtable in the image -- or only an abstract one: every slot but
    the destructor pair pure (-O0 keeps the inline base constructor and with it B's vtable),
  - has at least MIN_FAMILY derived classes, every one of them single inheritance (si), with no derived
    class of its own and one vtable, all with the same number of slots, and that number is a known layout:
      9 slots  libc++ std::__function::__base (with RTTI): ~, ~ [deleting], __clone(), __clone(p), destroy(),
               destroy_deallocate(), operator() [6], target(), target_type()
      3 slots  a destructor pair and one call operator [2] (a hand-written function<R(A...)>)
  - is not an exception type: no class of the family (or B) is caught or in an exception specification
    (an exception hierarchy has the 3-slot shape: ~, ~ [deleting], what()).
Names, where the binary kept them (mangled or a bind), add evidence and also catch the families smaller than
MIN_FAMILY: a type named std::__function::__func<...> is a std::function closure.

A single-method interface with a virtual destructor and three or more leaf implementations has the 3-slot
shape too; it is a callback interface in all but name, and is reported as a closure (a limit, see wiki
classes.md). Pure Python, no Binary Ninja import.
"""
MIN_FAMILY = 3
LAYOUTS = {9: ("std::function", 6), 3: ("function object", 2)}
_FUNC = "__function6__func"   # libc++ std::__function::__func<F, A, R(Args...)>
_BASE = "__function6__base"   # libc++ std::__function::__base<R(Args...)>


class Closure:
    __slots__ = ("addr", "base", "layout", "invoke_index", "invoke", "evidence")

    def __init__(self, addr, base, layout, invoke_index, invoke, evidence):
        self.addr = addr                  # the closure class's typeinfo
        self.base = base                  # the wrapper's base typeinfo (None: not in the image)
        self.layout = layout              # "std::function" / "function object"
        self.invoke_index = invoke_index  # the call operator's slot
        self.invoke = invoke              # its function: code address, "pure" or an import name
        self.evidence = evidence          # "layout", "name", "layout+name"

    def __repr__(self):
        return "Closure(%#x %s invoke [%d] %s)" % (self.addr, self.layout, self.invoke_index, self.evidence)


def _names(t):
    return [t.name or ""] + list(t.bind_names)


def _named(t, part):
    return t is not None and any(part in n for n in _names(t))


def _primary(t):
    p = [vt for vt in t.vtables if vt.primary]
    return p[0] if p else None


def caught(tables, resolve=None):
    """the typeinfos the exception tables (cpp/lsda.py LSDAs) catch or list in a specification: addresses, and
    the names the image gave a type entry (an import's __ZTI name; in BN also a local typeinfo's display name,
    e.g. typeinfo_for_Err) -- resolve(name) -> [raw name | address] adds what that name stands for"""
    out = set()
    for table in tables:
        for cs in table.call_sites:
            for c in cs.clauses:
                for t in (c.type if isinstance(c.type, list) else [c.type]):
                    if t is not None:
                        out.add(t)
                    if isinstance(t, str) and resolve is not None:
                        out.update(resolve(t))
    return out


def _caught(t, caught):
    return t.addr in caught or any(n in caught for n in ["__ZTI" + (t.name or "")] + list(t.bind_names))


def classify(types, caught=()):
    """{typeinfo address: Closure} for the closure classes; everything else is a class. caught: the typeinfos
    the exception tables catch (caught()), a veto"""
    derived = {}
    for a, t in types.items():
        for b, _of in t.bases:
            if isinstance(b, int):
                derived.setdefault(b, []).append(a)
    out = {}
    for b, ds in derived.items():
        bt = types.get(b)
        if bt is None or bt.bases:
            continue
        vts = [types[d].vtables for d in ds]
        if len(ds) < MIN_FAMILY or any(types[d].kind != "si" or d in derived or len(v) != 1 or not v[0].primary
                                       for d, v in zip(ds, vts)):
            continue
        sizes = set(len(v[0].slots) for v in vts)
        if len(sizes) != 1 or sizes.copy().pop() not in LAYOUTS:
            continue
        layout, idx = LAYOUTS[sizes.pop()]
        own = [vt for vt in bt.vtables if vt.construction_for is None]
        if own and not (len(own) == 1 and own[0].primary and all(x == "pure" for x in own[0].slots[2:])):
            continue  # the base implements more than its destructors: a class hierarchy
        if _caught(bt, caught) or any(_caught(types[d], caught) for d in ds):
            continue  # exception types
        named = _named(bt, _BASE) or any(_named(types[d], _FUNC) for d in ds)
        if layout != "std::function" and named:
            continue  # a std::function name on a non-std::function layout: do not guess
        for d in ds:
            out[d] = Closure(d, b, layout, idx, types[d].vtables[0].slots[idx], "layout+name" if named else "layout")
    # by name alone: the families too small for the layout rule
    for a, t in types.items():
        if a in out or _caught(t, caught) or not _named(t, _FUNC):
            continue
        vt = _primary(t)
        if vt is not None and len(vt.slots) == 9:
            base = t.bases[0][0] if t.bases and isinstance(t.bases[0][0], int) else None
            out[a] = Closure(a, base, "std::function", 6, vt.slots[6], "name")
    return out


def bases(types, closures):
    """{base typeinfo: layout} of the wrappers' bases (in the image) that the closures derive from"""
    return dict((c.base, c.layout) for c in closures.values() if c.base is not None and c.base in types)


def format_closure(c):
    """the line for the class scan dump"""
    inv = "%#x" % c.invoke if isinstance(c.invoke, int) else str(c.invoke)
    return "  closure %s  invoke [%d] %s  (%s)" % (c.layout, c.invoke_index, inv, c.evidence)
