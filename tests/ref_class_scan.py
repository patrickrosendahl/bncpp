"""REFERENCE ONLY (Binary Ninja is the source of truth): the class scan (cpp/rtti.py) on the file itself.

Classic dyld info only: cpp/macho.py does not decode chained fixups (rebases stay raw chained words there).
cpp/macho.py supplies every classic dyld bind, so typeinfo kinds come from the vptr binds ('bind'), where BN
falls back to the layout (tests/bn_class_scan.py) -- comparing the two outputs checks that fallback. The numbers
on bncpp-21 / bncpp-25 come from this.

  python3 -I tests/ref_class_scan.py BINARY [--out FILE] [--compare BN_FILE [--diff]] [name-substring ...]

--compare checks tests/bn_class_scan.py's output against this scan, per typeinfo: 'same'; 'names' (only the
real names from binds differ); 'lost import' (BN shows an imported base or slot as "import ?" or under another
name, or ends a vtable before its trailing imported slots: binds BN does not keep, bncpp-25); otherwise 'structure' (kind, bases, vtables or slots disagree), and
'missing' / 'extra'. Exit 1 if any typeinfo differs in structure.
"""
import collections, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cpp import macho, rtti, unwind_info

args = sys.argv[1:]
show_diff = "--diff" in args
args = [a for a in args if a != "--diff"]


def option(name):
    if name not in args:
        return None
    i = args.index(name)
    v = args[i + 1]
    del args[i:i + 2]
    return v


out, against = option("--out"), option("--compare")
m = macho.MachO(args[0])
types = rtti.scan(m)
if out:
    with open(out, "w") as f:
        f.write("\n".join(rtti.format_scan(types)) + "\n")

starts = set(f.addr for f in unwind_info.functions(m))
kinds = collections.Counter(t.kind for t in types.values())
names = collections.Counter(t.name_kind for t in types.values())
print("typeinfo objects: %d  %s" % (len(types), dict(kinds)))
print("names: %d mangled, %d hex hashes, %d none; %d with a real name from a bind" % (
    names["mangled"], names["hash"], names["none"], sum(1 for t in types.values() if t.bind_names)))
with_vt = [t for t in types.values() if t.vtables]
code = [s for t in with_vt for vt in t.vtables for s in vt.slots if isinstance(s, int)]
print("classes with a vtable: %d (%d vtables, %d secondary); %d slots, %d/%d point at a known function start" % (
    len(with_vt), sum(len(t.vtables) for t in with_vt), sum(1 for t in with_vt for vt in t.vtables if vt.offset_to_top),
    sum(len(vt.slots) for t in with_vt for vt in t.vtables), sum(1 for s in code if s in starts), len(code)))
for want in args[1:]:
    sel = {a: t for a, t in types.items() if any(want in n for n in [t.name or ""] + t.bind_names)}
    print("\n".join(rtti.format_scan(sel, m.symbol_name)))


def blocks(lines):
    """typeinfo address -> (header fields, [body lines])"""
    d, cur = {}, None
    for line in lines:
        if line.startswith("typeinfo"):
            f = line.split()
            cur = int(f[1], 16)
            d[cur] = (f, [])
        elif cur is not None and line.strip():
            d[cur][1].append(line.rstrip())
    return d


def _imported(line):
    """a base / slot line naming an import, as (prefix, name)"""
    for key in ("base import ", "] "):
        i = line.find(key)
        if i >= 0:
            rest = line[i + len(key):]
            if key == "base import " or not rest.startswith("0x") and rest != "pure":
                return line[:i + len(key)], rest
    return None


def _drop_trailing_imports(rb, bb):
    """ref body with each vtable cut to BN's slot count where BN lost trailing imported slots, else None"""
    out, i, j, changed = [], 0, 0, False
    while i < len(rb):
        x = rb[i]
        if x.startswith("  vtable") and j < len(bb) and bb[j].startswith("  vtable"):
            nr, nb = int(x.split()[-2]), int(bb[j].split()[-2])
            if nb < nr and x.split()[1] == bb[j].split()[1]:
                tail = rb[i + 1 + nb:i + 1 + nr]
                if not all(_imported(t) for t in tail):
                    return None
                out.append(bb[j])
                out += rb[i + 1:i + 1 + nb]
                i, j, changed = i + 1 + nr, j + 1 + nb, True
                continue
        out.append(x)
        i, j = i + 1, j + 1
    return out if changed else None


def classify(ref, bn):
    (rh, rb), (bh, bb) = ref, bn
    if rh[2] != bh[2] or rh[4] != bh[4]:
        return "structure"
    lost = False
    if len(rb) != len(bb):
        rb = _drop_trailing_imports(rb, bb)
        if rb is None or len(rb) != len(bb):
            return "structure"
        lost = True
    for x, y in zip(rb, bb):
        if x == y:
            continue
        ix, iy = _imported(x), _imported(y)
        if ix and iy and ix[0] == iy[0]:
            lost = True
            continue
        return "structure"
    if lost:
        return "lost import"
    return "same" if rh == bh else "names"


if against:
    import difflib
    r, b = blocks(rtti.format_scan(types)), blocks(open(against).read().splitlines())
    counts = collections.Counter()
    for a in sorted(set(r) | set(b)):
        state = "missing" if a not in b else "extra" if a not in r else classify(r[a], b[a])
        counts[state] += 1
        if state not in ("same", "names", "lost import"):
            print("%#x %s" % (a, state))
            if show_diff and state == "structure":
                print("\n".join(difflib.unified_diff([" ".join(r[a][0])] + r[a][1], [" ".join(b[a][0])] + b[a][1],
                                                    "file", "bn", lineterm="", n=1)))
    print(", ".join("%d %s" % (counts[k], k) for k in ("same", "names", "lost import", "structure", "missing", "extra")))
    sys.exit(1 if counts["structure"] else 0)
