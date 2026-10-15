"""Offline test / scorer for the sloppy line matcher (bncpp-36), no Binary Ninja.

Builds tests/linemap/src/*.c for each variant with -g, takes the DWARF line table as ground truth
(ref_dwarf_lines.py), extracts the stripped binary's features (ref_bin_features.py, names off), matches against
the source tree (shared.linematch), and scores line-inside-range / exact / function hits per variant
(shared.linemap.score). The matcher is reference tooling; in BN the same features come from the view.

  python3 -I tests/ref_line_match.py                 # build + score every fixture x variant
  python3 -I tests/ref_line_match.py --keep          # leave the built binaries in .scratch for inspection
Thresholds (regression guard): line inside the range >= 80% and functions 100% on every variant.
"""
import os, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)

import ref_bin_features, ref_dwarf_lines  # noqa: E402
from shared import linematch  # noqa: E402
from shared.linemap import format_score, score  # noqa: E402
from shared.srcindex import SourceTree  # noqa: E402

SRC = os.path.join(HERE, "linemap", "src")
# a dedicated subdir: .scratch/linemap also holds the kernel feature dump (tests/ref_kernel_linemap.py), which
# a cleanup of the whole directory deleted once (2026-10-15) -- never rmtree the parent again
OUT = os.path.join(REPO, ".scratch", "linemap", "fixture")
VARIANTS = [("arm64", 0), ("arm64", 2), ("x86_64", 0), ("x86_64", 2)]


def build(src, arch, opt, out):
    obj = os.path.join(out, "o.o")
    dylib = os.path.join(out, "sample.dylib")
    subprocess.run(["clang", "-arch", arch, "-O%d" % opt, "-g", "-fno-inline", "-c", src, "-o", obj], check=True)
    subprocess.run(["clang", "-arch", arch, "-dynamiclib", "-undefined", "dynamic_lookup", obj, "-o", dylib],
                   check=True)
    subprocess.run(["dsymutil", dylib, "-o", dylib + ".dSYM"], check=True, capture_output=True)
    return dylib


def run(keep=False):
    tree = SourceTree(SRC, exts=(".c",))
    ok = True
    for src_name in sorted(os.listdir(SRC)):
        if not src_name.endswith(".c"):
            continue
        src = os.path.join(SRC, src_name)
        for arch, opt in VARIANTS:
            out = os.path.join(OUT, "%s-O%d" % (arch, opt))
            os.makedirs(out, exist_ok=True)
            dylib = build(src, arch, opt, out)
            truth = ref_dwarf_lines.read(dylib + ".dSYM", arch)
            bf = ref_bin_features.read(dylib, arch, names=False)
            guess = linematch.build(bf, tree)
            s = score(truth, guess)
            n = max(s["scored"], 1)
            inside = 100.0 * s["inside"] / n
            label = "%s %s-O%d" % (src_name, arch, opt)
            bad = inside < 80.0 or s["functions_hit"] < s["functions"]
            ok = ok and not bad
            print("%-22s %s%s" % (label, format_score(s), "   <-- BELOW THRESHOLD" if bad else ""))
    if not keep:
        import shutil
        shutil.rmtree(OUT, ignore_errors=True)
    return ok


if __name__ == "__main__":
    sys.exit(0 if run("--keep" in sys.argv) else 1)
