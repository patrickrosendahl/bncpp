"""Offline test of the dSYM export (bncpp-38), no Binary Ninja.

Per fixture x variant (as tests/ref_line_match.py): the matcher's line map of the stripped binary is written as a
dSYM (shared/dsym.py), then checked with the toolchain:
  - dwarfdump --verify passes and --uuid gives the binary's UUID
  - read back (ref_dwarf_lines.py): every exported row comes back with its address range, file and first line,
    every function with its name and range
  - atos on our dSYM gives function and file:line at each function start
  python3 -I tests/ref_dsym.py [--keep]
"""
import os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)

import ref_bin_features, ref_dwarf_lines  # noqa: E402
from ref_line_match import SRC, VARIANTS, build  # noqa: E402
from shared import dsym, linematch  # noqa: E402
from shared.srcindex import SourceTree  # noqa: E402

OUT = os.path.join(REPO, ".scratch", "linemap", "dsym")
MIN_CONF = 0.0      # the fixture's rows all go out: the round trip checks every one


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def check(dylib, arch, tree, out):
    """[problem] for one built fixture"""
    bad = []
    guess = linematch.build(ref_bin_features.read(dylib, arch, names=False), tree)
    ds = os.path.join(out, "ours.dSYM")
    shutil.rmtree(ds, ignore_errors=True)
    counts = dsym.write(guess, dylib, ds, MIN_CONF, arch)
    dw = os.path.join(ds, "Contents", "Resources", "DWARF", os.path.basename(dylib))
    v = _run(["xcrun", "dwarfdump", "--verify", dw])
    if v.returncode != 0 or "No errors." not in v.stdout:
        bad.append("verify: " + (v.stdout + v.stderr).strip().splitlines()[-1])
    want = re.search(r"UUID: (\S+)", _run(["xcrun", "dwarfdump", "--uuid", dylib]).stdout).group(1)
    got = re.search(r"UUID: (\S+)", _run(["xcrun", "dwarfdump", "--uuid", dw]).stdout)
    if not got or got.group(1) != want:
        bad.append("uuid %s != %s" % (got and got.group(1), want))
    back = ref_dwarf_lines.read(dw, arch)
    rows = [r for r in guess.rows() if r.conf >= MIN_CONF and r.first > 0]
    lost = 0
    for r in rows:
        b = back.at(r.start)
        if b is None or b.file != r.file or b.first != r.first or b.end < r.end and back.at(b.end) is None:
            lost += 1
    if lost:
        bad.append("rows: %d of %d not read back" % (lost, len(rows)))
    names = {(f.name, f.start, f.end) for f in back.functions}
    fl = [f for f in guess.functions if (f.name, f.start, f.end) not in names]
    if fl:
        bad.append("functions not read back: %s" % [f.name for f in fl])
    # atos: function (in file:line) at each function start
    for f in guess.functions:
        a = _run(["atos", "-arch", arch, "-o", dw, "-l", "0", "%#x" % f.start]).stdout.strip()
        r = guess.at(f.start)
        want_fl = "(%s:%d)" % (os.path.basename(r.file), r.first) if r is not None else ""
        if not a.startswith(f.name) or want_fl not in a:
            bad.append("atos %#x: %r, want %s %s" % (f.start, a, f.name, want_fl))
    return counts, len(rows), bad


def run(keep=False):
    tree = SourceTree(SRC, exts=(".c",))
    ok = True
    for src_name in sorted(os.listdir(SRC)):
        if not src_name.endswith(".c"):
            continue
        for arch, opt in VARIANTS:
            out = os.path.join(OUT, "%s-O%d" % (arch, opt))
            os.makedirs(out, exist_ok=True)
            dylib = build(os.path.join(SRC, src_name), arch, opt, out)
            counts, n, bad = check(dylib, arch, tree, out)
            ok = ok and not bad
            print("%s %s-O%d  units %d, functions %d, rows %d (%d checked)%s" % (
                src_name, arch, opt, counts["units"], counts["functions"], counts["rows"], n,
                "" if not bad else "\n    " + "\n    ".join(bad)))
    if not keep:
        shutil.rmtree(OUT, ignore_errors=True)
    return ok


if __name__ == "__main__":
    sys.exit(0 if run("--keep" in sys.argv) else 1)
