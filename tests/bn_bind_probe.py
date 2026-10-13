"""Which Mach-O dyld binds does Binary Ninja keep? Evidence for bncpp-25 (report to Vector35).

Read-only. Decodes the file's classic dyld bind opcodes (cpp/macho.py, reference only) per stream (bind / weak /
lazy) and looks each bound slot up in BN's relocations: 'has' = a relocation with the same symbol, 'other' = a
relocation with a different symbol (BN's name from the symbol table), 'none' = no relocation with a symbol.
  bnrun --bndb BINARY_OR_BNDB --timeout 300 tests/bn_bind_probe.py [-- PATH_OF_THE_RAW_BINARY]
"""
import collections, os, sys

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
sys.path.insert(0, REPO)
from cpp import macho  # noqa: E402

path = sys.argv[1] if len(sys.argv) > 1 else bv.file.original_filename
if path.endswith(".bndb"):
    path = path[:-5]
m = macho.MachO(path)
m.binds  # parse once
d = m._dyld_info
streams = collections.defaultdict(list)  # slot -> [(stream, symbol, addend)]
for name, (off, size) in zip(("bind", "weak", "lazy"), ((d[2], d[3]), (d[4], d[5]), (d[6], d[7]))):
    m._binds = {}
    if size:
        m._run_binds(m.image[off:off + size])
    for slot, (sym, addend) in m._binds.items():
        streams[slot].append((name, sym, addend))

counts, examples = collections.Counter(), collections.defaultdict(list)
for slot, entries in sorted(streams.items()):
    bn = [r.symbol.raw_name for r in bv.relocations_at(slot) if r.symbol is not None]
    names = [e[1] for e in entries]
    state = "has" if any(n in bn for n in names) else ("other" if bn else "none")
    key = ("+".join(e[0] for e in entries), "addend" if any(e[2] for e in entries) else "no addend", state)
    counts[key] += 1
    if state != "has" and len(examples[key]) < 3:
        examples[key].append("%#x %s+%#x  BN: %s, reads %#x" % (
            slot, names[0], entries[0][2], bn or "-", bv.read_pointer(slot)))
print("%s: %d bound slots" % (os.path.basename(path), len(streams)))
for k, v in sorted(counts.items()):
    print("  %-10s %-9s %-5s %5d" % (k + (v,)))
for k, ex in sorted(examples.items()):
    print("%s:" % " / ".join(k))
    for e in ex:
        print("    " + e)
