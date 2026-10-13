"""REFERENCE ONLY (Binary Ninja is the source of truth): offline class scan of a Mach-O with classic dyld info.

Typeinfo objects from the bind opcodes, their names and bases, and the vtables that reference them (Itanium
layout). The numbers on bncpp-21 / bncpp-25 come from this.

  python3 -I tests/ref_class_scan.py BINARY [name-substring ...]
"""
import collections, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cpp import macho, unwind_info

KIND = {"__ZTVN10__cxxabiv117__class_type_infoE": "class",
        "__ZTVN10__cxxabiv120__si_class_type_infoE": "si",
        "__ZTVN10__cxxabiv121__vmi_class_type_infoE": "vmi"}

m = macho.MachO(sys.argv[1])
text = m.section("__TEXT", "__text")
starts = set(f.addr for f in unwind_info.functions(m))


def q(a):
    try:
        return struct.unpack("<Q", m.read(a, 8))[0]
    except Exception:
        return None


def cstr(a, n=300):
    try:
        b = m.read(a, n)
    except Exception:
        return None
    return b.split(b"\0", 1)[0].decode("latin1")


def is_code(v):
    return v is not None and text.addr <= v < text.addr + text.size


# 1. typeinfo objects: a slot bound to __cxxabiv1::*_type_info's vtable (+16)
types = {}
for slot, (sym, addend) in m.binds.items():
    k = KIND.get(sym)
    if k:
        name_ptr = q(slot + 8)
        t = {"kind": k, "name": cstr(name_ptr) if name_ptr else None, "bases": []}
        if k == "si":
            t["bases"] = [(q(slot + 16), 0)]
        elif k == "vmi":
            flags, count = struct.unpack("<II", m.read(slot + 16, 8))
            for i in range(count):
                bti, off_flags = q(slot + 24 + 16 * i), q(slot + 32 + 16 * i)
                t["bases"].append((bti, off_flags))
        types[slot] = t

# 2. vtables: [offset_to_top][typeinfo] then code pointers; find every qword == a typeinfo address
data_secs = [s for s in m.sections if s.segname in ("__DATA", "__DATA_CONST") and s.offset]
vtables = collections.defaultdict(list)  # typeinfo -> [(vtable addr point, offset_to_top, slots)]
for s in data_secs:
    d = m.section_data(s)
    for i in range(8, len(d) - 8, 8):
        v = struct.unpack_from("<Q", d, i)[0]
        if v in types:
            ott = struct.unpack_from("<q", d, i - 8)[0]
            if not (-0x10000 < ott <= 0):
                continue
            slots, j = [], i + 8
            while j + 8 <= len(d):
                w = struct.unpack_from("<Q", d, j)[0]
                bound = m.binds.get(s.addr + j)
                if is_code(w):
                    slots.append(w)
                elif bound and "pure_virtual" in bound[0]:
                    slots.append("pure")
                elif bound and w == 0 and not bound[0].startswith("__ZTI"):
                    slots.append(bound[0])  # imported virtual (inherited from a library class)
                else:
                    break
                j += 8
            if slots:
                vtables[v].append((s.addr + i + 8, ott, slots))

# report
kinds = collections.Counter(t["kind"] for t in types.values())
named = [t for t in types.values() if t["name"]]
mangled = [t for t in named if t["name"][:1] in "NSZ" or t["name"][:1].isdigit() and not all(c in "0123456789abcdef" for c in t["name"])]
hashed = [t for t in named if t["name"] and all(c in "0123456789abcdef" for c in t["name"])]
print("typeinfo objects: %d  %s" % (len(types), dict(kinds)))
print("names: %d readable (mangled), %d hex hashes, %d other" % (len(mangled), len(hashed), len(named) - len(mangled) - len(hashed)))
with_vt = [ti for ti in types if vtables.get(ti)]
nslots = sum(len(vt[2]) for ti in with_vt for vt in vtables[ti])
in_starts = sum(1 for ti in with_vt for vt in vtables[ti] for sl in vt[2] if isinstance(sl, int) and sl in starts)
total_int = sum(1 for ti in with_vt for vt in vtables[ti] for sl in vt[2] if isinstance(sl, int))
print("classes with a vtable: %d (%d vtables incl. secondary); %d slots, %d/%d point at a known function start"
      % (len(with_vt), sum(len(vtables[t]) for t in with_vt), nslots, in_starts, total_int))
secondary = sum(1 for t in with_vt for vt in vtables[t] if vt[1] < 0)
print("secondary vtables (offset-to-top < 0): %d" % secondary)
if len(sys.argv) > 2:
    for want in sys.argv[2:]:
        for ti, t in types.items():
            if t["name"] and want in t["name"]:
                print("\n%s  typeinfo %#x  kind %s" % (t["name"], ti, t["kind"]))
                for b, of in t["bases"]:
                    print("   base %s (%#x)%s" % (types.get(b, {}).get("name"), b or 0,
                                               "  offset/flags %#x" % of if t["kind"] == "vmi" else ""))
                for vt, ott, slots in vtables.get(ti, []):
                    print("   vtable %#x  offset-to-top %d  %d slots: %s" % (
                        vt, ott, len(slots), " ".join("%#x" % x if isinstance(x, int) else x for x in slots[:12])))
