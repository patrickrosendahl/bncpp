"""Class layouts past the vptr (bncpp-22): constructors and destructors, class sizes, base subobjects and fields,
from what the code does with the objects. Builds on cpp/rtti.py (the classes) and cpp/rtti_types.py (struct X {
X::VTable* vptr; } and 'X* this' on the virtual functions).

  ctors       a function that stores a vtable address point of class X into its own 'this' (the first parameter
              or a copy of it), at offset 0, is a constructor or destructor of X; with stores of several classes
              of one hierarchy (a derived constructor inlines its base's) the most derived one. Such functions get
              'X* this' too, so their field accesses count. A tiny function that only passes its 'this' on to a
              constructor of X (the complete-object constructor C1 tail-calling the base-object one C2) is one
              too (found from the operator new sites, by the caller: tests/bn_class_fields.py).
  sizes       operator new(N) whose result receives X's vptr at offset 0, or goes to a constructor of X as 'this':
              X is N bytes. The most frequent N (a tie: the largest). Inlined constructors store the vptr of
              each class of the chain in turn: only the most derived class of one call counts.
  bases       si: the base at offset 0; vmi: each non-virtual base at offset_flags >> 8 (virtual bases sit at
              run-time offsets: left out). In BN: base structures.
  fields      the offsets the code accesses through 'X*' (BN's create_structure_from_offset_access, after the
              constructors are typed). An access of a derived class inside a base's range belongs to the base
              (moved there, unless the base has a member at that offset); the base's width is its size, else its
              own accesses' end. Width of X: its size, else the end of its bases and members.
  names       vptr at 0; a member someone named in the existing struct keeps its name and type; else a name
              given for (class, offset) (overrides, e.g. from another session's schema); else field_<offset>.
              An override inside a base subobject names the base's member (unless the base has another one there).

Pure Python, no Binary Ninja import: member types are opaque values the caller supplies (BN Type objects).
"""


class Member:
    __slots__ = ("offset", "name", "type", "size", "source")

    def __init__(self, offset, name, type, size, source):
        self.offset, self.name, self.type, self.size = offset, name, type, size
        self.source = source  # "access" / "lifted" / "user" / "override" / "vptr"

    def __repr__(self):
        return "Member(%#x %s %s)" % (self.offset, self.name, self.source)


class ClassLayout:
    __slots__ = ("typeinfo", "name", "width", "width_from", "bases", "members", "notes")

    def __init__(self, typeinfo, name):
        self.typeinfo = typeinfo
        self.name = name
        self.width = 8
        self.width_from = "vptr"  # "new" (operator new) / "members" / "vptr"
        self.bases = []           # [(base typeinfo, offset)]
        self.members = []         # [Member], sorted by offset
        self.notes = []           # [str]: overrides moved into a base or dropped (the review)


def ancestors(types, addr):
    seen, todo = set(), [addr]
    while todo:
        t = types.get(todo.pop())
        for b, _of in (t.bases if t is not None else ()):
            if isinstance(b, int) and b in types and b not in seen:
                seen.add(b)
                todo.append(b)
    return seen


def ctor_classes(types, stores):
    """{function: class typeinfo} from {function: [(offset in this, class typeinfo, offset_to_top)]} -- the
    vptr stores on a function's own 'this'; only primary-vtable stores at offset 0 decide, and they must be
    one hierarchy (the most derived class wins)"""
    out = {}
    for f, ss in stores.items():
        cls = set(c for off, c, ott in ss if off == 0 and ott == 0 and c in types)
        leaf = [c for c in cls if all(o == c or o in ancestors(types, c) for o in cls)]
        if len(leaf) == 1:
            out[f] = leaf[0]
    return out


def class_sizes(sites, ctors, types):
    """{class typeinfo: size} from operator new sites: [(class typeinfo or None, constructor called or None,
    size, call address)] -- a site names the class by the vptr stored into the new object or by the constructor it
    calls; inlined constructors store each class's vptr of the chain in turn, so per call only the most derived
    class gets the size (none if the classes are not one hierarchy)"""
    calls = {}
    for cls, ctor, size, call in sites:
        c = cls if cls is not None else ctors.get(ctor)
        if c is not None and size:
            calls.setdefault((call, size), set()).add(c)
    counts = {}
    for (_call, size), cls in calls.items():
        leaf = [c for c in cls if all(o == c or o in ancestors(types, c) for o in cls)]
        if len(leaf) == 1:
            counts.setdefault(leaf[0], {})
            counts[leaf[0]][size] = counts[leaf[0]].get(size, 0) + 1
    return {c: max(n.items(), key=lambda kv: (kv[1], kv[0]))[0] for c, n in counts.items()}


def base_offsets(t, types):
    """[(base typeinfo, offset)] of the non-virtual bases this image defines"""
    if t.kind == "si":
        b = t.bases[0][0] if t.bases else None
        return [(b, 0)] if isinstance(b, int) and b in types else []
    out = []
    for b, of in t.bases:
        if isinstance(b, int) and b in types and of is not None and not of & 1:
            out.append((b, of >> 8))
    return out


def layouts(types, labels, sizes, accesses, existing=None, overrides=None, vptr_type=None, int_type=None,
            widths=None):
    """{class typeinfo: ClassLayout} for every class with a primary vtable or accesses.

    accesses: {typeinfo: {offset: (size, type)}} -- what the code accesses through 'X*' (BN)
    existing: {typeinfo: [(offset, name, type, size, user?)]} -- the struct's members now; user = someone named
              it (not vptr / field_* / an override name), kept as it is
    overrides: {(label, offset): (name, type or None)}
    vptr_type: vptr_type(label) -> the type of X's vptr member
    int_type:  int_type(n) -> an n-byte integer type: an access wider than the gap to the next member (BN types
               a 16-byte SSE copy of two fields as int128) is narrowed to the widest of 8 / 4 / 2 / 1 bytes that
               fits; a name without a type the code never accesses (a sub-object whose address is taken) becomes
               a 1-byte placeholder
    widths:    {typeinfo: width of the struct now} -- once a struct has a base structure, BN reports the derived
               class's accesses as the base's too (get_code_refs_for_type_field): a base class keeps its size from
               new, else the width of its struct, and its accesses past it are the derived classes', dropped;
               any class is cut to its size from new and a base to fit into each derived class with a size
               (width "derived" when that cuts it)"""
    existing = existing or {}
    overrides = overrides or {}
    classes = [a for a, t in types.items() if any(vt.primary for vt in t.vtables) or a in accesses]
    acc = {a: dict(accesses.get(a, {})) for a in classes}
    out = {a: ClassLayout(a, labels[a]) for a in classes}
    for a in classes:
        out[a].bases = [(b, off) for b, off in base_offsets(types[a], types) if b in out]
    depth = {a: len(ancestors(types, a)) for a in classes}
    # cap: no part of a class lies past its size from new, and a base subobject fits into every derived object of
    # a known size (deepest classes first, so a cap reaches all the way up); BN reports a sibling's accesses for
    # every class of the chain, which alone would make the bases wider than the objects
    cap = {}
    for a in sorted(classes, key=lambda a: -depth[a]):
        c = min([v for v in (sizes.get(a), cap.get(a)) if v is not None], default=None)
        if c is None:
            continue
        cap[a] = c
        for b, off in out[a].bases:
            if c - off > 0:
                cap[b] = min(cap.get(b, c - off), c - off)
    kept = {}
    for b in set(b for a in classes for b, _off in out[a].bases):
        w = (widths or {}).get(b)
        if b not in sizes and w is not None and w > 8:
            kept[b] = min(w, cap.get(b, w))
    for a, c in list(cap.items()) + list(kept.items()):
        acc[a] = {off: v for off, v in acc[a].items() if off < c}

    # widths before lifting: the size, else the end of the own accesses and bases (fixed, so lifting is stable)
    def own_end(a, seen=()):
        ends = [8] + [off + s for off, (s, _t) in acc[a].items()]
        ends += [off + width(b, seen + (a,)) for b, off in out[a].bases if b not in seen]
        return max(ends)

    memo = {}

    def width(a, seen=()):
        if a not in memo:
            memo[a] = sizes[a] if a in sizes else kept[a] if a in kept else own_end(a, seen)
            memo[a] = min(memo[a], cap.get(a, memo[a]))
        return memo[a]

    for a in classes:
        out[a].width = min(max(width(a), own_end(a)), cap.get(a, 1 << 62))
        out[a].width_from = "new" if a in sizes and sizes[a] >= own_end(a) else (
            "derived" if a in cap and out[a].width == cap[a] else "members" if out[a].width > 8 else "vptr")

    # lift a derived class's accesses inside a base into the base, deepest classes first (so they go all the way up)
    for a in sorted(classes, key=lambda a: -depth[a]):
        for off in sorted(acc[a]):
            for b, boff in out[a].bases:
                if boff <= off < boff + out[b].width and off != 0:  # 0: the class's own vptr
                    s, ty = acc[a].pop(off)
                    acc[b].setdefault(off - boff, (s, ty))
                    break

    # the same for the overrides: a name given for a derived class's offset inside a base names the base's member
    # (one object, one layout); a different name there already is a conflict: the base's stays, the review says so
    overrides = dict(overrides)
    for a in sorted(classes, key=lambda a: -depth[a]):
        for (lab, off), (name, oty) in sorted(overrides.items(), key=lambda kv: kv[0][1]):
            if lab != labels[a] or off == 0:
                continue
            for b, boff in out[a].bases:
                if boff <= off < boff + out[b].width:
                    del overrides[(lab, off)]
                    key, there = (labels[b], off - boff), overrides.get((labels[b], off - boff))
                    if there is None or there == (name, oty):
                        overrides[key] = (name, oty)
                        out[a].notes.append("override %#x %s -> base %s %#x" % (off, name, labels[b], off - boff))
                    else:
                        out[a].notes.append("override %#x %s dropped: base %s %#x is %s" % (
                            off, name, labels[b], off - boff, there[0]))
                    break

    for a in classes:
        lay, label = out[a], labels[a]
        taken = {}
        for off, name, ty, size, user in existing.get(a, []):
            if user:
                taken[off] = Member(off, name, ty, size, "user")
        if any(vt.primary for vt in types[a].vtables) and 0 not in taken and vptr_type is not None:
            taken[0] = Member(0, "vptr", vptr_type(label), 8, "vptr")
        in_base = [(boff, boff + out[b].width) for b, boff in lay.bases]
        for off, (size, ty) in sorted(acc[a].items()):
            if off in taken or any(s <= off < e for s, e in in_base):
                continue
            name, oty = overrides.get((label, off), (None, None))
            taken[off] = Member(off, name or "field_%x" % off, oty if oty is not None else ty, size,
                                "override" if name else "access")
        for (lab, off), (name, oty) in overrides.items():  # a named offset the code did not show: still a member
            if lab == label and off not in taken and not any(s <= off < e for s, e in in_base):
                if oty is None and int_type is not None:
                    taken[off] = Member(off, name, int_type(1), 1, "override")
                elif oty is not None:
                    taken[off] = Member(off, name, oty, None, "override")
        offs = sorted(taken)
        for o, nxt in zip(offs, offs[1:] + [lay.width]):
            m = taken[o]
            narrow = m.source == "access" or (m.source == "override" and overrides.get((label, o), (0, 0))[1] is None)
            if int_type is not None and narrow and m.size and m.size > nxt - o > 0:
                n = next(k for k in (8, 4, 2, 1) if k <= nxt - o)
                taken[o] = Member(o, m.name, int_type(n), n, m.source)
        lay.members = [taken[o] for o in offs]
    return out


def format_layouts(lays, types=None):
    """the layouts as text (review / suite), one block per class"""
    out = []
    for a in sorted(lays):
        lay = lays[a]
        out.append("struct %s  (%#x bytes, from %s)%s" % (lay.name, lay.width, lay.width_from, "".join(
            "  base %s @ %#x" % (lays[b].name, off) for b, off in lay.bases)))
        for m in lay.members:
            out.append("  %#6x %-24s %s  [%s]" % (m.offset, m.name, m.type, m.source))
        out += ["  note: " + n for n in lay.notes]
    return out
