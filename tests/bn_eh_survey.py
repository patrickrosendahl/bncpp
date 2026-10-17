# Run inside Binary Ninja via the script bridge, after tests/bn_dev_load.py:
#   bnrun --parallel --timeout 600 tests/bn_eh_survey.py [--env DUMP_TESTS=TestCatchAll,...]
# bncpp-2 premise check: what BN makes of each function with an LSDA, per suite binary. For the owner's range
# (compact unwind: from its entry to the next one) -- which BN functions cover it (the owner, landing pads split
# off as sub_..., tail pieces), which instructions no function covers (lost code), and per landing pad: a function
# starting there, the functions containing it, and whether the owner itself reaches it.
# Output: .scratch/eh/<variant>/TestX.survey, and a summary line per binary.
# CREATE_PADS=1: first create a function at every landing pad BN has none at (cpp/landing_pads.py, bncpp-4; the
# view is a throwaway one, nothing is saved), then survey -> .scratch/eh-pads/.
import glob, importlib, os
import binaryninja as _bn

REPO = globals().get("CPP_REPO", "/Users/patrick/dev/binary-cpp")
_dev = getattr(_bn, "_cpp_dev", None)
if _dev is None or "pkgname" not in _dev:
    raise RuntimeError("run tests/bn_dev_load.py first")
_lsda = importlib.import_module(_dev["pkgname"] + ".cpp.lsda")
_uw = importlib.import_module(_dev["pkgname"] + ".cpp.unwind_info")
_bnimage = importlib.import_module(_dev["pkgname"] + ".cpp.bnimage")
_lp = importlib.import_module(_dev["pkgname"] + ".cpp.landing_pads")
_env = globals().get("env") or {}
_only = _env.get("DUMP_TESTS") or os.environ.get("DUMP_TESTS")
_bins = sorted(glob.glob(os.path.join(REPO, "tests/suite/bin/*/*.dylib")))
if _only:
    _bins = [b for b in _bins if any(os.path.basename(b).startswith(p) for p in _only.split(","))]
_create = (_env.get("CREATE_PADS") or os.environ.get("CREATE_PADS")) == "1"
_out = os.path.join(REPO, ".scratch/eh-pads" if _create else ".scratch/eh")
_FILL = ("nop", "int3", "ud2", "brk", "udf")  # padding and traps: not code that can be lost


def _instructions(bv, start, end):
    """[(addr, length)] by linear sweep (the owner's range is contiguous code)"""
    out, a = [], start
    while a < end:
        info = bv.arch.get_instruction_info(bv.read(a, 16), a)
        n = info.length if info is not None and info.length else bv.arch.instr_alignment or 1
        out.append((a, n))
        a += n
    return out


def _filler(bv, a, n):
    """alignment padding or a trap (after a call that does not return)"""
    data = bv.read(a, n)
    if not data.strip(b"\x00"):
        return True
    toks = bv.arch.get_instruction_text(data, a)
    mnem = str(toks[0][0]).strip() if toks and toks[0] else ""
    return mnem.startswith(_FILL)


def _covered(bv, a):
    return [f for f in bv.get_functions_containing(a)]


def _name(f):
    return f.symbol.full_name


def _survey(bv):
    img = _bnimage.BNImage(bv)
    units = sorted(_uw.functions(img), key=lambda u: u.addr)
    text = bv.sections.get("__text")
    lines, stats = [], {"owners": 0, "pads": 0, "pad functions": 0, "pads in owner": 0, "pads in no function": 0,
                        "lost bytes": 0, "split pieces": 0}
    for i, u in enumerate(units):
        if u.lsda is None:
            continue
        end = units[i + 1].addr if i + 1 < len(units) else text.end
        table = _lsda.parse_function(img, u.addr)
        owner = bv.get_function_at(u.addr)
        stats["owners"] += 1
        lines.append("%s @ %#x .. %#x  (owner %s)" % (img.symbol_name(u.addr) or "?", u.addr, end,
                                                       "found" if owner else "MISSING"))
        # coverage of the owner's range
        pieces, lost = {}, []
        for a, n in _instructions(bv, u.addr, end):
            fs = _covered(bv, a)
            for f in fs:
                pieces.setdefault(f.start, f)
            if not fs and not _filler(bv, a, n):
                if lost and lost[-1][1] == a:
                    lost[-1][1] = a + n
                else:
                    lost.append([a, a + n])
        for s, f in sorted(pieces.items()):
            if f.start != u.addr:
                stats["split pieces"] += 1
            lines.append("  function %#x %s%s" % (s, _name(f), "" if u.addr <= s < end else "  (starts outside)"))
        for a, b in lost:
            stats["lost bytes"] += b - a
            lines.append("  LOST %#x .. %#x  (%d bytes in no function)" % (a, b, b - a))
        # landing pads
        pads = {}
        for cs in table.call_sites:
            if cs.landing_pad is not None:
                kinds = ", ".join("catch(%s)" % (c.type if c.type is not None else "...") if c.kind == "catch"
                                  else c.kind for c in cs.clauses) or "cleanup"
                pads.setdefault(cs.landing_pad, kinds)
        for pad, kinds in sorted(pads.items()):
            stats["pads"] += 1
            at = bv.get_function_at(pad)
            fs = _covered(bv, pad)
            in_owner = owner is not None and any(f.start == owner.start for f in fs)
            stats["pad functions"] += at is not None
            stats["pads in owner"] += in_owner
            stats["pads in no function"] += not fs
            lines.append("  pad +%#x %-28s %s" % (pad - u.addr, kinds, "; ".join(filter(None, [
                "function here" if at is not None else "",
                "in owner" if in_owner else "",
                "in " + ", ".join(_name(f) for f in fs if owner is None or f.start != owner.start)
                if any(owner is None or f.start != owner.start for f in fs) else "",
                "IN NO FUNCTION" if not fs else ""]))))
        lines.append("")
    return lines, stats


_total = {}
for _path in _bins:
    _variant = os.path.basename(os.path.dirname(_path))
    _bv = _bn.load(_path)
    try:
        _made = len(_lp.recover(_bv)[1]) if _create else 0
        _lines, _stats = _survey(_bv)
        _stats["created"] = _made
    finally:
        _bv.file.close()
    if not _stats["owners"]:
        continue
    _dir = os.path.join(_out, _variant)
    os.makedirs(_dir, exist_ok=True)
    with open(os.path.join(_dir, os.path.basename(_path)[:-6] + ".survey"), "w", encoding="utf-8") as _fh:
        _fh.write("\n".join(_lines) + "\n")
    for k, v in _stats.items():
        _total[k] = _total.get(k, 0) + v
    print("%-10s %-24s %s" % (_variant, os.path.basename(_path)[:-6], ", ".join("%s %d" % kv for kv in _stats.items())))
print("TOTAL", ", ".join("%s %d" % kv for kv in _total.items()))
