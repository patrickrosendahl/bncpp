"""The binary-cpp test suite, modelled on Fernflower / Vineflower's SingleClassesTest.

One small C++ source per feature (src/TestX.cpp), compiled for every variant (arch x optimisation level) into a
dylib (bin/<variant>/TestX.dylib, committed). The Pseudo Cpp output of each is checked against a reviewed
reference (results/<variant>/TestX.pcpp, the counterpart of Fernflower's testData/results/TestX.dec). When a
change improves the output, review the diff and accept it as the new reference.

  python3 tests/suite/suite.py build [TestX ...]         # clang++ every (or the named) test for every variant
  bnrun --timeout 60 tests/bn_dev_load.py                # in BN: register Pseudo Cpp devN
  bnrun --parallel --timeout 600 tests/bn_dump.py        # in BN: .scratch/suite/out/<variant>/TestX.{pc,pcpp,lsda}
  python3 tests/suite/suite.py compare [--diff] [--strict] [TestX ...]   # exit 1 if any output differs from its reference
  python3 tests/suite/suite.py accept [--force] TestX ...  # output -> reference (after reviewing the diff)
  python3 tests/suite/suite.py check [--max K=V ...] [--worst N] [--show NAME] [--compare] [--strict] [TestX ...]  # no-loss + flaws
  python3 tests/suite/suite.py ref-lsda                  # offline: .scratch/suite/ref/<variant>/TestX.lsda
  python3 tests/suite/suite.py crosscheck [--diff] [TestX ...] # BN .lsda vs the offline one (exit 1: structure)
  python3 tests/suite/suite.py lint                      # pyflakes over the plugin and tests/ (exit 1: a finding)

check (bncpp-8, shared/compare.py): per function, every call and string literal of its Pseudo C (.pc: the HLIL as
BN prints it) must still be in its Pseudo Cpp, plus flaw counters (temporaries, gotos, exception plumbing, render
errors, a catch clause in the LSDA but no try, ...) and the class APPLYs in .fields that stopped at the round
limit ('unsettled', bncpp-60); exit 1 if a total exceeds its gate (GATES, or --max K=V). check runs lint first.
--compare (bncpp-131) adds the totals of the references (results/: their .pcpp and .fields with the current .pc and
.lsda) and the deltas -- the before / after numbers for a ticket; lost_calls etc. of the references are only
indicative when BN's functions changed since they were accepted.

Stamps (bncpp-134): compare and check print a WARNING for outputs without a stamp, from several plugin states or not
from the working tree's plugin / dump scripts / binaries; --strict makes such a warning exit 1, and accept refuses
the named tests' outputs then unless --force (bncpp-141) -- a scripted 'compare && accept' takes no stale output.

lint (bncpp-133): pyflakes over the plugin (__init__.py, constants.py, cpp/, shared/) and tests/ -- a redefined
function or an undefined name is silent in BN until a 10 min dump shows the damage. The bridge scripts (tests/)
get bv and env from bnrun, so they count as builtins there.

Checked outputs (all from bn_dump.py, i.e. through Binary Ninja): .pcpp (the view), .lsda (the decoded
exception tables, cpp/lsda.py on cpp/bnimage.py), .classes (the class scan, cpp/rtti.py, with the names
cpp/rtti_names.py gives), .fields (the class pipeline) and .ehpath (the exception path from the functions in
EH_PATHS). .pc is Pseudo C of the same functions (BN's own output, for
comparison; not checked). ref-lsda decodes the same tables from the files themselves (cpp/macho.py, reference
only -- Binary Ninja is the source of truth); crosscheck compares the two with the names masked (BN demangles
and names import slots its own way), so it catches a wrong section, segment, import slot or unwind entry.
"""
import difflib, filecmp, hashlib, json, os, re, shutil, struct, subprocess, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SRC = os.path.join(HERE, "src")
BIN = os.path.join(HERE, "bin")
RESULTS = os.path.join(HERE, "results")
OUT = os.path.join(REPO, ".scratch", "suite", "out")
REF = os.path.join(REPO, ".scratch", "suite", "ref")  # offline reference decodes (ref-lsda)

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
    "TestTryInBranch",        # try inside one branch of an if / else and inside a switch case (bncpp-67)
    "TestStringTemporary",    # library destructors on the unwind path
    "TestCatchClass",         # the program's own exception classes: throw statements, typed catch objects
    # readability passes (from binary-jvm)
    "TestFolding",            # fold single-use temporaries into their use, evaluation-order safe (bncpp-13)
    "TestTernary",
    "TestBooleanReturn",
    "TestIncrement",
    "TestLoopConditions",
    "TestSwitch",
    "TestTryFolding",         # the passes in functions with try regions: never across a try block (bncpp-84)
    "TestNoFold",             # shapes the passes above must leave alone or keep in order (bncpp-90)
    "TestLargeShapes",        # what the passes leave in a large function (bncpp-103: nhv_dddd_proc's shapes)
    # classes: RTTI and vtables (.classes; cpp/rtti.py), one source in four builds
    "TestVirtual",               # classic dyld info
    "TestVirtualChained",        # chained fixups
    "TestVirtualHashed",         # classic, undefined nlist names hashed like SynthV's (BN drops binds, bncpp-25)
    "TestVirtualChainedHashed",  # chained, nlist hashed
    "TestClassChain",            # inlined constructor chain: one new object gets each class's vptr (.fields)
    "TestPointerFields",         # fields holding object pointers: typed Y* from the stores (.fields, bncpp-34)
    "TestNoVtableBase",          # bases without a vtable in the image, anchored by the RTTI base lists (bncpp-31)
    "TestClosure",               # lambdas in std::function / a function object vs same-shaped classes (bncpp-23)
    "TestAnchoredBaseFields",    # polymorphic anchored base with fields as the second base (bncpp-58/59)
    "TestInteriorFields",        # fields reached only through untyped helpers / an interior pointer; floats (bncpp-33)
    "TestVirtualThrow",          # exception path through virtual calls (bncpp-66; .ehpath)
    "TestCastThrow",             # ... through calls on dynamic_cast results (bncpp-95; .ehpath)
    "TestThrowHelpers",          # throw sites behind libc++'s __throw_* helpers and own wrappers (bncpp-92)
    "TestClosureThrow",          # ... through std::function: params, a forwarder, a member (bncpp-109; .ehpath)
    # names hashed like SynthV's raw slices
    "TestCatchAllHashed",        # clang's terminate helper and std::terminate unnamed: guards found anyway (bncpp-71)
]

# tests built differently from src/TestX.cpp with -undefined dynamic_lookup: name -> (source, link flags, hash
# the undefined nlist names? True, or the list of names to hash). Hashing keeps the dyld info intact (the dylib
# stays valid), like an obfuscator.
BUILDS = {
    "TestVirtual": ("TestVirtual", ["-Wl,-no_fixup_chains"], False),
    "TestVirtualChained": ("TestVirtual", ["-Wl,-fixup_chains"], False),
    "TestVirtualHashed": ("TestVirtual", ["-Wl,-no_fixup_chains"], True),
    "TestVirtualChainedHashed": ("TestVirtual", ["-Wl,-fixup_chains"], True),
    "TestCatchAllHashed": ("TestCatchAll", ["-undefined", "dynamic_lookup"],
                           ["___clang_call_terminate", "__ZSt9terminatev"]),
}
RENAME_NLIST = os.path.join(REPO, "tests", "repro_nlist_binds", "rename_nlist.py")


def variant_name(arch, opt):
    return "%s-O%d" % (arch, opt)


def fix_uuid(dylib):
    """set a thin 64-bit Mach-O's LC_UUID to an MD5 of the file (UUID zeroed, code signature left out), then
    rehash the linker's ad-hoc signature in place (codesign would replace it with a larger one and grow
    __LINKEDIT)"""
    with open(dylib, "rb") as fh:
        b = bytearray(fh.read())
    assert struct.unpack_from("<I", b, 0)[0] == 0xfeedfacf, dylib
    off, uuid_at, sig_at = 32, None, len(b)
    for _ in range(struct.unpack_from("<I", b, 16)[0]):
        cmd, size = struct.unpack_from("<II", b, off)
        if cmd == 0x1b:  # LC_UUID
            uuid_at = off + 8
        elif cmd == 0x1d:  # LC_CODE_SIGNATURE: dataoff
            sig_at = struct.unpack_from("<I", b, off + 8)[0]
        off += size
    b[uuid_at:uuid_at + 16] = bytes(16)
    u = bytearray(hashlib.md5(bytes(b[:sig_at])).digest())
    u[6] = (u[6] & 0x0f) | 0x30  # RFC 4122 version 3 (name-based, MD5), like ld's own UUIDs
    u[8] = (u[8] & 0x3f) | 0x80
    b[uuid_at:uuid_at + 16] = u
    # SuperBlob (big-endian) -> CodeDirectory: the code-slot hashes are per page up to codeLimit; an ad-hoc
    # directory is not itself signed, so new page hashes are all it needs (x86_64: ld signs nothing)
    magic, _, count = struct.unpack_from(">III", b, sig_at) if sig_at < len(b) else (0xfade0cc0, 0, 0)
    assert magic == 0xfade0cc0, dylib
    for i in range(count):
        _, blob = struct.unpack_from(">II", b, sig_at + 12 + 8 * i)
        cd = sig_at + blob
        if struct.unpack_from(">I", b, cd)[0] != 0xfade0c02:  # CSMAGIC_CODEDIRECTORY
            continue
        hash_off, _, _, n_slots, code_limit = struct.unpack_from(">IIIII", b, cd + 16)
        hash_size, hash_type, _, page_log2 = struct.unpack_from(">BBBB", b, cd + 36)
        assert hash_type == 2 and hash_size == 32, dylib  # SHA-256
        page = 1 << page_log2
        for s in range(n_slots):
            at = cd + hash_off + 32 * s
            b[at:at + 32] = hashlib.sha256(bytes(b[s * page:min((s + 1) * page, code_limit)])).digest()
    with open(dylib, "wb") as fh:
        fh.write(b)
    if count:
        subprocess.run(["codesign", "-v", dylib], check=True)


def build(names):
    for arch, opt in VARIANTS:
        out = os.path.join(BIN, variant_name(arch, opt))
        os.makedirs(out, exist_ok=True)
        for t in names:
            # helpers from TestTryCatch stay undefined in the other dylibs (imports, like calls to other classes)
            src, flags, hashed = BUILDS.get(t, (t, ["-undefined", "dynamic_lookup"], False))
            dylib = os.path.join(out, t + ".dylib")
            subprocess.run(["clang++", "-arch", arch, "-std=c++17", "-O%d" % opt, "-fexceptions", "-dynamiclib"]
                           + flags + ["-install_name", "@rpath/%s.dylib" % t, "-o", dylib,
                                      os.path.join(SRC, src + ".cpp")], check=True)
            if opt == 0:
                # at -O0 the driver passes ld -no_deduplicate, which gives a random LC_UUID: every rebuild would
                # rewrite the tracked dylib (bncpp-114). A UUID from the content keeps rebuilds byte-identical.
                fix_uuid(dylib)
            if hashed:
                names_ = hashed if hashed is not True else subprocess.run(
                    ["nm", "-u", dylib], capture_output=True, text=True, check=True).stdout.split()
                subprocess.run([sys.executable, "-I", RENAME_NLIST, dylib, dylib] + names_, check=True,
                               stdout=subprocess.DEVNULL)
                subprocess.run(["codesign", "-f", "-s", "-", dylib], check=True, stderr=subprocess.DEVNULL)
    print("built %d tests x %d variants into %s" % (len(names), len(VARIANTS), BIN))


CHECKED = ("pcpp", "lsda", "classes", "fields", "ehpath")  # output kinds compared against a reference

# .ehpath (bncpp-117): the exception path from these functions (tests/bn_eh_path.py after the class pipeline, one
# run per entry); only these tests have one. An entry is a FROM: a name, '*' wildcards, '|' alternatives (the
# first that names a function in the variant -- a lambda's operator() is inlined into __func's at -O2)
EH_PATHS = {
    "TestVirtualThrow": ["Job::run"],
    "TestCastThrow": ["Batch::flush"],
    "TestClosureThrow": ["guarded_apply(int)::$_0::operator()|__func<guarded_apply*operator()",
                         "guarded_forward(int)::$_0::operator()|__func<guarded_forward*operator()",
                         "schedule(Worker*, int)::$_0::operator()|__func<schedule*operator()"],
}


def kinds(t):
    return [k for k in CHECKED if k != "ehpath" or t in EH_PATHS]


def pairs(names):
    for arch, opt in VARIANTS:
        v = variant_name(arch, opt)
        for t in names:
            for ext in kinds(t):
                f = "%s.%s" % (t, ext)
                yield v, f, os.path.join(OUT, v, f), os.path.join(RESULTS, v, f)


# stamps (bncpp-134): out/<variant>/.stamps.json {TestX: {kind: stamp}}, written by bn_dump.py per output. A stamp
# holds the hashes of what produced it: 'plugin' the dev-loaded package (top-level *.py, cpp/, shared/ -- what
# bn_dev_load.py copies; constants.py without its LANGUAGE_NAME), 'scripts' the dump scripts read from the repo
# (+ EH_PATHS), 'input' the binary (+ its .names); 'dev' the language name, 'at' the time. compare / check warn when
# the outputs come from more than one plugin state or not from the working tree's; bn_dump.py RESUME=1 skips a
# binary whose outputs all carry the current stamp (bncpp-130).
STAMPS = ".stamps.json"
DUMP_SCRIPTS = ["bn_dump.py", "bn_class_apply.py", "bn_class_types.py", "bn_class_fields.py", "bn_catch_types.py",
                "bn_eh_path.py"]


def _sha(parts):
    h = hashlib.sha1()
    for p in parts:
        h.update(p if isinstance(p, bytes) else p.encode("utf-8"))
        h.update(b"\0")
    return h.hexdigest()[:12]


def plugin_hash(root=REPO):
    """the plugin sources under root (the repo or a dev load's /tmp/cpp_devN), as bn_dev_load.py copies them"""
    parts = []
    for sub in ("", "cpp", "shared"):
        d = os.path.join(root, sub)
        for f in sorted(os.listdir(d)) if os.path.isdir(d) else ():
            if f.endswith(".py"):
                data = open(os.path.join(d, f), "rb").read()
                if sub == "" and f == "constants.py":
                    data = re.sub(rb'LANGUAGE_NAME = "[^"]*"', b"", data)
                parts += [os.path.join(sub, f), data]
    return _sha(parts)


def scripts_hash():
    return _sha([open(os.path.join(REPO, "tests", f), "rb").read() for f in DUMP_SCRIPTS] + [repr(EH_PATHS)])


def input_hash(binary):
    names = os.path.join(SRC, os.path.splitext(os.path.basename(binary))[0] + ".names")
    return _sha([open(binary, "rb").read()] + ([open(names, "rb").read()] if os.path.exists(names) else []))


def read_stamps(variant_dir):
    try:
        with open(os.path.join(variant_dir, STAMPS), encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def write_stamps(variant_dir, test, stamps):
    """merge {kind: stamp} of one test into the variant's stamp file"""
    allst = read_stamps(variant_dir)
    allst.setdefault(test, {}).update(stamps)
    tmp = os.path.join(variant_dir, STAMPS + ".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(allst, fh, indent=1, sort_keys=True)
    os.replace(tmp, os.path.join(variant_dir, STAMPS))


def stamp_warnings(names):
    """warnings about the outputs pairs(names) reads: unstamped, from several plugin states, not from the working
    tree's sources / scripts / binaries"""
    plugin, scripts = plugin_hash(), scripts_hash()
    devs, unstamped, stale = {}, 0, {"plugin": 0, "scripts": 0, "input": 0}
    inputs, cache = {}, {}
    for arch, opt in VARIANTS:
        v = variant_name(arch, opt)
        if v not in cache:
            cache[v] = read_stamps(os.path.join(OUT, v))
        for t in names:
            for k in kinds(t):
                if not os.path.exists(os.path.join(OUT, v, "%s.%s" % (t, k))):
                    continue
                st = cache[v].get(t, {}).get(k)
                if st is None:
                    unstamped += 1
                    continue
                devs.setdefault(st["plugin"], set()).add(st.get("dev", "?"))
                binary = os.path.join(BIN, v, t + ".dylib")
                if binary not in inputs:
                    inputs[binary] = input_hash(binary) if os.path.exists(binary) else None
                for key, now in (("plugin", plugin), ("scripts", scripts), ("input", inputs[binary])):
                    stale[key] += st.get(key) != now
    out = []
    if unstamped:
        out.append("%d output(s) without a stamp (dumped before bncpp-134)" % unstamped)
    if len(devs) > 1:
        out.append("outputs from %d plugin states: %s" % (len(devs), "; ".join(
            "%s %s" % (h, "/".join(sorted(d))) for h, d in sorted(devs.items()))))
    what = {"plugin": "the working tree's plugin sources (edited since the dev load, or an older dump)",
            "scripts": "the current dump scripts / EH_PATHS", "input": "the current binaries (rebuilt since)"}
    out += ["%d output(s) not from %s" % (n, what[k]) for k, n in stale.items() if n]
    return out


def ref_lsda():
    """decode every test dylib's exception tables from the file (offline, reference only) into
    .scratch/suite/ref/<variant>/TestX.lsda -- the same format as bn_dump.py's .lsda"""
    sys.path.insert(0, REPO)
    from cpp import lsda as L, macho
    n = 0
    for arch, opt in VARIANTS:
        v = variant_name(arch, opt)
        os.makedirs(os.path.join(REF, v), exist_ok=True)
        for t in TESTS:
            m = macho.MachO(os.path.join(BIN, v, t + ".dylib"))
            lines = []
            for start, table in sorted(L.parse_all(m).items()):
                lines += L.format_lsda(table, m.symbol_name(start), m.segment_start(start)) + [""]
                n += 1
            with open(os.path.join(REF, v, t + ".lsda"), "w") as f:
                f.write("\n".join(lines) if lines else "no LSDA\n")
    print("decoded %d LSDAs into %s" % (n, REF))


_HEADER = re.compile(r"^\S.*?(  lsda base\+)")  # function name up to the LSDA address
_CLAUSE = re.compile(r"\b(catch|throw)\((?!\.\.\.\))[^()]*(?:\([^()]*\)[^()]*)*\)")


def mask_names(line):
    """an .lsda line with the names that BN and the file spell differently replaced by placeholders:
    the function name of a header line, the type of each catch(...) / throw(...) (catch (...) stays)"""
    return _CLAUSE.sub(lambda m: m.group(1) + "(<type>)", _HEADER.sub(r"<function>\1", line))


def crosscheck(names, show_diff):
    """BN's .lsda (bn_dump.py) against the offline reference (ref-lsda): 'structure' = differs with the
    names masked (a real disagreement), 'names' = only the spelling of names differs (expected)"""
    counts = {"same": 0, "names": 0, "structure": 0, "missing": 0}
    for arch, opt in VARIANTS:
        v = variant_name(arch, opt)
        for t in names:
            bn, ref = os.path.join(OUT, v, t + ".lsda"), os.path.join(REF, v, t + ".lsda")
            if not (os.path.exists(bn) and os.path.exists(ref)):
                state = "missing"
            else:
                a, b = open(ref).read().splitlines(), open(bn).read().splitlines()
                if a == b:
                    state = "same"
                elif list(map(mask_names, a)) == list(map(mask_names, b)):
                    state = "names"
                else:
                    state = "structure"
                    if show_diff:
                        sys.stdout.writelines(l + "\n" for l in difflib.unified_diff(
                            list(map(mask_names, a)), list(map(mask_names, b)), "offline", "bn", lineterm=""))
            counts[state] += 1
            if state in ("structure", "missing"):
                print("%-10s %-26s %s" % (v, t, state))
    print(", ".join("%d %s" % (n, k) for k, n in counts.items()))
    return 0 if counts["structure"] == counts["missing"] == 0 else 1


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
    return 0 if counts["ok"] == sum(1 for _ in pairs(names)) else 1


def warn_stamps(names):
    """print the stamp warnings for names; their count"""
    warnings = stamp_warnings(names)
    for w in warnings:
        print("WARNING", w)
    return len(warnings)


# flaw counters over a function's Pseudo Cpp (string literals removed, comments kept)
_REG = r"(?:[xwqdsbhv]\d+|r[a-d]x|e[a-d]x|[re]?(?:si|di|bp|sp)|r\d+[dwb]?|[xyz]mm\d+|[a-d][lh]|[a-d]x)"
COUNTERS = {
    "temps": re.compile(r"\b(?:entry_)?%s(?:_\d+)?\b|\bvar_[0-9a-f]+(?:_\d+)?\b|\b(?:x|w|r)\d+_\d+\b" % _REG),
    "gotos": re.compile(r"\bgoto\b"),
    "labels": re.compile(r"^\s*label_\w+:", re.M),
    # a `do` without a `{` on the next line is Pseudo C's brace-less form (a braced do-while is no flaw, bncpp-83)
    "while_true": re.compile(r"\bwhile \(true\)|\bdo[ \t]*\n(?![ \t]*\{)", re.M),
    "tailcalls": re.compile(r"/\* tailcall \*/"),
    # a cleanup pad's closing _Unwind_Resume (its last statement: only comments up to the function's '}') is the
    # pad's normal end, not plumbing leaking into a catch body (bncpp-142)
    "plumbing": re.compile(r"(?<![\w$])_*(?:cxa_begin_catch|cxa_end_catch|cxa_rethrow|cxa_get_exception_ptr|"
                           r"Unwind_Resume(?![^;]*;(?:\s|/\*.*?\*/|//[^\n]*)*\}\s*\Z)|clang_call_terminate)\s*\(",
                           re.S),
    "render_errors": re.compile(r"could not render"),
}
DISTINCT = ("temps",)
# calls the try/catch rendering may hide (bncpp-7): not lost when they vanish; a throw statement (bncpp-65) hides the
# allocation, ___cxa_throw and the declaration of the exception variable (BN's type syntax `__offset(vtable, 0x10)*`)
MAY_VANISH = re.compile(r"_*(?:cxa_begin_catch|cxa_end_catch|cxa_rethrow|cxa_get_exception_ptr|Unwind_Resume|"
                        r"clang_call_terminate|cxa_allocate_exception|cxa_throw|offset)")
# the name needs a separator before it: `catch (T)` has none (the type's last character is not a variable)
CATCH_VAR = r"catch \((?:const )?[\w:<>, ]+?(?: const)?(?:\s*[&*]\s*|\s+)(\w+)\)"
# gates (bncpp-8): nothing lost, no render error, nothing structurally broken; readability counters only report
GATES = {"lost_calls": 0, "lost_strings": 0, "render_errors": 0, "unbalanced": 0, "truncated": 0,
         "leaked_catch_var": 0, "missing": 0, "unsettled": 0}
_FUNC = re.compile(r"^// .* @ (0x[0-9a-f]+)$")  # keyed by the address (overloads share a name)


def _lsda_catches(path):
    """{function name: catch clauses} from an .lsda dump (functions whose landing pads catch something)"""
    out, cur = {}, None
    for line in open(path).read().splitlines() if os.path.exists(path) else ():
        if line and not line[0].isspace():
            cur = line.split("  lsda base+")[0]
        elif cur and "catch" in line:
            out[cur] = out.get(cur, 0) + line.count("catch")
    return out


def _check_rows(names, root, show, quiet=False):
    """per-function rows and the totals of check: .pcpp and .fields from root (OUT, or RESULTS for the before
    numbers), .pc and .lsda always from OUT (the references hold no .pc)"""
    sys.path.insert(0, REPO)
    from shared import compare as C
    say = (lambda *a: None) if quiet else print
    rows, missing = [], 0
    for arch, opt in VARIANTS:
        v = variant_name(arch, opt)
        for t in names:
            pcpp, pc = os.path.join(root, v, t + ".pcpp"), os.path.join(OUT, v, t + ".pc")
            if not (os.path.exists(pcpp) and os.path.exists(pc)):
                say("%-10s %-26s no output" % (v, t))
                missing += 1
                continue
            ref = dict((k, body) for k, _h, body in C.split_functions(open(pc).read(), _FUNC))
            catches = _lsda_catches(os.path.join(OUT, v, t + ".lsda"))
            first = {}  # the .lsda names the function, not its address: C1/C2 ctors share a name, count it once
            for addr, header, body in C.split_functions(open(pcpp).read(), _FUNC):
                r = C.check_function(body, ref.get(addr), COUNTERS, DISTINCT, MAY_VANISH, CATCH_VAR)
                name = header[3:].rsplit(" @ ", 1)[0]
                has_try = bool(re.search(r"\btry\b", C.strip_comments(C.strip_strings("\n".join(body)))))
                r["missing_try"] = 0
                if name in catches:
                    if name not in first:
                        first[name] = r
                        r["missing_try"] = 1
                    if has_try:
                        first[name]["missing_try"] = 0
                r["function"] = "%s %s %s" % (v, t, name)
                rows.append(r)
                if show and show in r["function"] and not quiet:
                    print("=" * 30, r["function"], {k: x for k, x in r.items() if x and k != "function"})
                    print("\n".join(body))
    keys = list(COUNTERS) + ["unbalanced", "truncated", "dead_code", "leaked_catch_var", "missing_try",
                             "lost_calls", "lost_strings", "stmts", "ref_stmts"]
    total = C.totals(rows, keys)
    total["missing"] = missing
    total["unsettled"] = 0  # bncpp-60: a class APPLY in the .fields dump that stopped at the round limit
    for arch, opt in VARIANTS:
        for t in names:
            path = os.path.join(root, variant_name(arch, opt), t + ".fields")
            for line in open(path).read().splitlines() if os.path.exists(path) else ():
                if line.startswith("not settled after "):
                    say("%-10s %-26s %s" % (variant_name(arch, opt), t, line))
                    total["unsettled"] += 1
    return rows, total


def check(names, maxes, worst, show, against_ref=False):
    """the no-loss check and the flaw counters of every test's Pseudo Cpp against its Pseudo C (bn_dump.py output);
    against_ref (--compare, bncpp-131): also the totals of the reference outputs and the deltas (before / after)"""
    sys.path.insert(0, REPO)
    from shared import compare as C
    rows, total = _check_rows(names, OUT, show)
    print("TOTAL", " ".join("%s=%d" % kv for kv in total.items()))
    if against_ref:
        _rows, before = _check_rows(names, RESULTS, None, quiet=True)
        print("REF  ", " ".join("%s=%d" % kv for kv in before.items()))
        delta = [(k, total[k] - before.get(k, 0)) for k in total if total[k] != before.get(k, 0)]
        print("DELTA", " ".join("%s=%+d" % kv for kv in delta) or "none")
    flaws = ("lost_calls", "lost_strings", "render_errors", "unbalanced", "truncated", "leaked_catch_var",
             "plumbing", "dead_code", "gotos", "missing_try", "temps")
    score = lambda r: sum((len(r.get(k, ())) if isinstance(r.get(k), list) else r.get(k, 0)) *
                          (1 if k == "temps" else 20) for k in flaws)
    for r in sorted(rows, key=score, reverse=True)[:worst]:
        if score(r) == 0:
            break
        print("  %-60s %s" % (r["function"], {k: r[k] for k in flaws if r.get(k)}))
    gates = dict(GATES)
    gates.update(dict((kv.split("=")[0], int(kv.split("=")[1])) for kv in maxes))
    failed = C.gate(total, gates)
    if failed:
        print("FAIL", ", ".join(failed))
        return 1
    print("gates ok (%s)" % ", ".join("%s<=%d" % kv for kv in sorted(gates.items())))
    return 0


LINT = [(["__init__.py", "constants.py", "cpp", "shared"], ""), (["tests"], "bv,env")]  # (paths, builtins)


def lint():
    """pyflakes over the plugin and tests/; the number of findings (printed), -1 without pyflakes"""
    exe = shutil.which("pyflakes")
    cmd = [exe] if exe else [sys.executable, "-m", "pyflakes"]
    found = 0
    for paths, builtins in LINT:
        r = subprocess.run(cmd + paths, cwd=REPO, capture_output=True, text=True,
                           env=dict(os.environ, PYFLAKES_BUILTINS=builtins))
        if r.returncode and not r.stdout and "No module named pyflakes" in r.stderr:
            print("lint: pyflakes not found (pip install pyflakes)")
            return -1
        lines = (r.stdout + r.stderr).splitlines()
        for line in lines:
            print(line)
        found += len(lines)
    print("lint: %d finding(s)" % found)
    return found


def accept(names):
    for v, t, out, ref in pairs(names):
        if os.path.exists(out):
            os.makedirs(os.path.dirname(ref), exist_ok=True)
            shutil.copy(out, ref)
            print("accepted", v, t)


def main(argv):
    cmd, args = (argv[0] if argv else "compare"), argv[1:]
    names = [a for i, a in enumerate(args) if not a.startswith("-") and "=" not in a
             and not (i and args[i - 1] in ("--worst", "--show"))]
    unknown = [n for n in names if n not in TESTS]
    if unknown:
        sys.exit("not registered: %s" % ", ".join(unknown))
    if cmd == "build":
        build(names or TESTS)
    elif cmd == "ref-lsda":
        ref_lsda()
    elif cmd == "crosscheck":
        return crosscheck(names or TESTS, "--diff" in args)
    elif cmd == "check":
        opt = lambda flag, default: args[args.index(flag) + 1] if flag in args else default
        maxes = [a for a in args if re.match(r"^\w+=\d+$", a)]
        names = [n for n in names if n in TESTS]
        linted = lint()
        failed = check(names or TESTS, maxes, int(opt("--worst", 15)), opt("--show", None), "--compare" in args)
        warned = warn_stamps(names or TESTS)
        return failed or int(linted != 0) or int(bool(warned) and "--strict" in args)
    elif cmd == "lint":
        return int(lint() != 0)
    elif cmd == "compare":
        differs = compare(names or TESTS, "--diff" in args)
        warned = warn_stamps(names or TESTS)
        return differs or int(bool(warned) and "--strict" in args)
    elif cmd == "accept":
        if not names and "--all" not in args:
            sys.exit("accept needs test names (or --all)")
        if warn_stamps(names or TESTS) and "--force" not in args:
            sys.exit("accept refused: stale or mixed outputs (rerun the dump, or --force)")
        accept(names or TESTS)
    else:
        sys.exit(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
