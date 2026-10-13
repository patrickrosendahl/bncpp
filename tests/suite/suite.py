"""The binary-cpp test suite, modelled on Fernflower / Vineflower's SingleClassesTest.

One small C++ source per feature (src/TestX.cpp), compiled for every variant (arch x optimisation level) into a
dylib (bin/<variant>/TestX.dylib, committed). The Pseudo Cpp output of each is checked against a reviewed
reference (results/<variant>/TestX.pcpp, the counterpart of Fernflower's testData/results/TestX.dec). When a
change improves the output, review the diff and accept it as the new reference.

  python3 tests/suite/suite.py build                     # clang++ every registered test for every variant
  bnrun --timeout 60 tests/bn_dev_load.py                # in BN: register Pseudo Cpp devN
  bnrun --parallel --timeout 600 tests/bn_dump.py        # in BN: .scratch/suite/out/<variant>/TestX.{pc,pcpp}
  python3 tests/suite/suite.py lsda                      # offline: .scratch/suite/out/<variant>/TestX.lsda
  python3 tests/suite/suite.py compare [--diff] [TestX ...]   # exit 1 if any output differs from its reference
  python3 tests/suite/suite.py accept TestX ...          # output -> reference (after reviewing the diff)

Checked outputs: .pcpp (the view, from bn_dump.py) and .lsda (the decoded exception tables, cpp/lsda.py --
no Binary Ninja needed). .pc is Pseudo C of the same functions (BN's own output, for comparison; not checked).
"""
import difflib, filecmp, os, shutil, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SRC = os.path.join(HERE, "src")
BIN = os.path.join(HERE, "bin")
RESULTS = os.path.join(HERE, "results")
OUT = os.path.join(REPO, ".scratch", "suite", "out")

VARIANTS = [("x86_64", 0), ("x86_64", 2), ("arm64", 0), ("arm64", 2)]

# the registry (Fernflower: register(JAVA_8, "TestX")); a test that is not listed is not built or checked
TESTS = [
    # exception handling (Itanium LSDA)
    "TestTryCatch",           # catch by type; also defines the helpers in common.h
    "TestMultiCatch",         # two catch clauses, base and derived types
    "TestCatchAll",           # catch (...)
    "TestRethrow",            # throw; and throwing a new exception from a catch
    "TestDestructorCleanup",  # cleanup-only landing pads
    "TestCleanupAndCatch",    # destructors and a catch in one landing pad
    "TestNestedTry",          # try inside try / inside a loop
    "TestStringTemporary",    # library destructors on the unwind path
    # readability passes (from binary-jvm)
    "TestTernary",
    "TestBooleanReturn",
    "TestIncrement",
    "TestLoopConditions",
    "TestSwitch",
]


def variant_name(arch, opt):
    return "%s-O%d" % (arch, opt)


def build():
    for arch, opt in VARIANTS:
        out = os.path.join(BIN, variant_name(arch, opt))
        os.makedirs(out, exist_ok=True)
        for t in TESTS:
            # helpers from TestTryCatch stay undefined in the other dylibs (imports, like calls to other classes)
            subprocess.run(["clang++", "-arch", arch, "-std=c++17", "-O%d" % opt, "-fexceptions", "-dynamiclib",
                            "-undefined", "dynamic_lookup", "-install_name", "@rpath/%s.dylib" % t,
                            "-o", os.path.join(out, t + ".dylib"), os.path.join(SRC, t + ".cpp")], check=True)
    print("built %d tests x %d variants into %s" % (len(TESTS), len(VARIANTS), BIN))


CHECKED = ("pcpp", "lsda")  # output kinds compared against a reference


def pairs(names):
    for arch, opt in VARIANTS:
        v = variant_name(arch, opt)
        for t in names:
            for ext in CHECKED:
                f = "%s.%s" % (t, ext)
                yield v, f, os.path.join(OUT, v, f), os.path.join(RESULTS, v, f)


def lsda():
    """decode every test dylib's exception tables (offline) into .scratch/suite/out/<variant>/TestX.lsda"""
    sys.path.insert(0, REPO)
    from cpp import lsda as L, macho
    n = 0
    for arch, opt in VARIANTS:
        v = variant_name(arch, opt)
        os.makedirs(os.path.join(OUT, v), exist_ok=True)
        for t in TESTS:
            m = macho.MachO(os.path.join(BIN, v, t + ".dylib"))
            lines = []
            for start, table in sorted(L.parse_all(m).items()):
                lines += L.format_lsda(table, m.symbol_name(start), m.text_base) + [""]
                n += 1
            with open(os.path.join(OUT, v, t + ".lsda"), "w") as f:
                f.write("\n".join(lines) if lines else "no LSDA\n")
    print("decoded %d LSDAs into %s" % (n, OUT))


def compare(names, show_diff):
    counts = {"ok": 0, "differs": 0, "no output": 0, "no reference": 0}
    for v, t, out, ref in pairs(names):
        if not os.path.exists(out):
            state = "no output"
        elif not os.path.exists(ref):
            state = "no reference"
        elif filecmp.cmp(out, ref, shallow=False):
            state = "ok"
        else:
            state = "differs"
        counts[state] += 1
        if state != "ok":
            print("%-10s %-26s %s" % (v, t, state))
            if state == "differs" and show_diff:
                sys.stdout.writelines(difflib.unified_diff(open(ref).readlines(), open(out).readlines(),
                                                           "reference", "output"))
    print(", ".join("%d %s" % (n, k) for k, n in counts.items()))
    return 0 if counts["ok"] == len(VARIANTS) * len(names) * len(CHECKED) else 1


def accept(names):
    for v, t, out, ref in pairs(names):
        if os.path.exists(out):
            os.makedirs(os.path.dirname(ref), exist_ok=True)
            shutil.copy(out, ref)
            print("accepted", v, t)


def main(argv):
    cmd, args = (argv[0] if argv else "compare"), argv[1:]
    names = [a for a in args if not a.startswith("-")]
    unknown = [n for n in names if n not in TESTS]
    if unknown:
        sys.exit("not registered: %s" % ", ".join(unknown))
    if cmd == "build":
        build()
    elif cmd == "lsda":
        lsda()
    elif cmd == "compare":
        return compare(names or TESTS, "--diff" in args)
    elif cmd == "accept":
        if not names and "--all" not in args:
            sys.exit("accept needs test names (or --all)")
        accept(names or TESTS)
    else:
        sys.exit(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
