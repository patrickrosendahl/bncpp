"""Kernel side of the sloppy line mapping (bncpp-36), offline / REFERENCE ONLY: adapt the BN feature dump
(tests/bn_line_features.py JSONL, taken from the kernel session's kernelcache view) to the matcher's input,
join the names from the kernel symbols file, run the lazy matcher against the xnu tree, and score:

  - function match vs the known names (the symbols file: ground truth for the matcher's choice)
  - __FILE__+__LINE__ anchor self-checks (the file exists in the tree, the line is inside it)
  - the share of binary functions matched at all, and the source functions / files hit

  python3 -I tests/ref_kernel_linemap.py [--limit N] [--skip N] [--out MAP.json] [--quiet]
                                         [--holdout] [--no-anchors] [--no-propagate] [--only kp|pl]
                                         [--no-exclude] [--no-order]
Defaults read .scratch/linemap/kernel/kernel.features.jsonl and sample/kernel/… symbols against the xnu tree;
--out writes the matched functions' line map (bncpp-37 format).
"""
import argparse, json, os, subprocess, sys, time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

from shared import linematch  # noqa: E402
from shared.linemap import LineMap, Row  # noqa: E402
from shared.srcindex import SourceTree  # noqa: E402

FEATS = os.path.join(REPO, ".scratch", "linemap", "kernel", "kernel.features.jsonl")
SYMBOLS = os.path.join(REPO, "sample", "kernel", "kernelcache.iphone10.symbols.txt")
XNU = os.path.join(REPO, "sample", "kernel", "xnu-8796.141.3")
# not in an arm64 kernel (bncpp-80): x86 code, and the user-space / build-host trees
XNU_ARM64_EXCLUDE = ("*/i386/*", "*/x86_64/*", "*-x86_64.c", "tests/*", "tools/*", "libsyscall/*", "libkdd/*",
                     "SETUP/*", "makedefs/*")
KERNEL_START = 0xfffffff0071b4000      # __TEXT_EXEC: the kernel proper (xnu); below it: prelinked kexts


def shared_row(start, end, fn, line):
    """an assert's __FILE__+__LINE__ pins the line exactly even when the file is not in the tree"""
    return Row(start, end, fn, line, line, linematch.CONF["file-line"], "file-line")


def read_symbols(path):
    """{address: name} from the kernel session's symbols file ('0xADDR _name', one leading _ dropped)"""
    out = {}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.split(None, 1)
            if len(parts) == 2:
                name = parts[1].strip()
                out[int(parts[0], 16)] = name[1:] if name.startswith("_") else name
    return out


def demangle(names, full=False):
    """c++filt a batch of Itanium names, if it is available: {mangled: 'OSObject::release'}; full: with the
    parameter list ('OSDictionary::setObject(char const*, OSMetaClassBase const*)')"""
    mangled = [n for n in names if n.startswith("_Z")]
    if not mangled:
        return {}
    try:
        p = subprocess.run(["c++filt"], input="\n".join(mangled), capture_output=True, text=True, timeout=60)
        if p.returncode != 0:
            return {}
        return dict(zip(mangled, [l if full else l.split("(")[0] for l in p.stdout.splitlines()]))
    except (OSError, subprocess.TimeoutExpired):
        return {}


def name_of(addr, symbols, demangled):
    """the source-side name of a symbol: a demangled C++ qualified name, else the plain name"""
    n = symbols.get(addr)
    if n is None:
        return None
    return demangled.get(n, n)


def bin_funcs(feats_path, symbols, demangled, limit=None, skip=0, all_symbols=None):
    """the dump's records as matcher input: {"start", "end", "name", "features"} with int addresses.
    Calls: the view names the functions the kernel session named, so a call to one shows as call '_name' (or a
    demangled signature), not as a bl -- it is turned back into a bl to the symbol's address (the call graph),
    with the call feature only where `symbols` (the seeds) carries the name: held-out names must not leak through
    their callers. all_symbols: every known {addr: name} for that reverse lookup (default: symbols). A bl whose
    target carries a seed symbol also becomes a call feature; Mach-O's leading _ is dropped; __builtin_ names
    also match the plain source name"""
    all_symbols = symbols if all_symbols is None else all_symbols
    by_name = {}
    for a, n in all_symbols.items():
        for key in {n, demangled.get(n, n)}:
            by_name[key] = None if key in by_name and by_name[key] != a else a   # an overload: ambiguous
    stats = {"recs": 0, "nohlil": 0, "skipped": 0, "errors": 0, "bl_named": 0, "builtin": 0, "call_to_bl": 0}
    with open(feats_path, encoding="utf-8") as fh:
        for line in fh:
            stats["recs"] += 1
            if skip and stats["recs"] <= skip:
                continue
            if limit is not None and stats["recs"] > skip + limit:
                break
            r = json.loads(line)
            if "nohlil" in r or "skipped" in r:
                stats["nohlil" if "nohlil" in r else "skipped"] += 1
                continue
            if "error" in r:
                stats["errors"] += 1
                continue
            feats = []
            for stmt in r.get("stmts", ()):
                for a, k, v in stmt[3]:
                    a = int(a, 16)
                    if k == "call":
                        key = v.split("(")[0] if "(" in v else (v[1:] if v.startswith("_") else v)
                        t = by_name.get(key)
                        if t is not None:
                            k, v = "bl", "%#x" % t
                            stats["call_to_bl"] += 1
                        else:
                            feats.append((a, "call", key))
                            if key.startswith("__builtin_") and len(key) > 10:  # the source shows the plain name
                                feats.append((a, "call", key[len("__builtin_"):]))
                                stats["builtin"] += 1
                            continue
                    if k == "bl":
                        t = int(v, 16) if v else None
                        feats.append((a, "bl", t))      # the call graph (propagation)
                        n = name_of(t, symbols, demangled) if t is not None else None
                        if n is not None:
                            feats.append((a, "call", n.split("::")[-1]))
                            stats["bl_named"] += 1
                    else:
                        feats.append((a, k, v))
            yield {"start": int(r["start"], 16), "end": int(r["end"], 16),
                   "name": name_of(int(r["start"], 16), symbols, demangled), "features": feats}
    yield stats  # sentinel: the caller cannot know the counts before the stream ends


def sig_of(addr, symbols, full):
    """the demangled parameter list of a C++ symbol ('char const*, OSMetaClassBase const*'), None for a C name"""
    f = full.get(symbols.get(addr))
    if f is None or "(" not in f:
        return None
    return f[f.index("(") + 1:f.rindex(")")]


def held_out(addr):
    """the stable half of the named functions kept back from the seeds (--holdout): scored, never used"""
    return (addr * 2654435761 >> 7) & 1 == 1


def agrees(name, sfunc):
    return sfunc.qualname == name or ("(" not in name and sfunc.qualname.split("::")[-1] == name.split("::")[-1])


def run(feats, symbols_path, xnu, out=None, limit=None, skip=0, quiet=False, holdout=False, anchors=True,
        prop=True, only=None, exclude=XNU_ARM64_EXCLUDE, order=True):
    """phases: (1) named functions -> their source function by name (the seeds); (2) the rest by anchors
    (file-line / string / rare const; the slow part, --no-anchors skips it); (3) call-graph propagation from the
    matched pairs; (3b) link order (the unmatched neighbours of one file's functions), then propagation again;
    (4) scores. --holdout seeds with half of the names and scores the other half: how well anchors, propagation
    and link order name a function nobody named"""
    symbols = read_symbols(symbols_path)
    demangled = demangle(set(symbols.values()))
    full = demangle(set(symbols.values()), full=True)
    truth = {}
    seed_symbols = symbols
    if holdout:
        seed_symbols = {a: n for a, n in symbols.items() if not held_out(a)}
    tree = SourceTree(xnu, exclude=exclude)
    print("source files: %d (%d excluded)" % (len(tree.paths), tree.excluded))
    index = linematch.FileIndex(tree)
    t0 = time.time()
    names = linematch.NameIndex(tree)
    m = LineMap({"name": "kernelcache.iphone10.dec"}, {"name": "xnu-8796.141.3", "root": xnu})
    tot = Counter()
    funcs = {}
    for bf in bin_funcs(feats, seed_symbols, demangled, limit, skip, symbols):
        if "recs" in bf:
            tot.update(bf)
            continue
        if only == "kp" and bf["start"] < KERNEL_START or only == "pl" and bf["start"] >= KERNEL_START:
            continue
        funcs[bf["start"]] = bf
        if bf["name"] is not None:
            bf["sig"] = sig_of(bf["start"], symbols, full)     # seeds only: a held-out signature would leak
        n = name_of(bf["start"], symbols, demangled)
        if n is not None:
            truth[bf["start"]] = n
    if not quiet:
        print("read %d functions, tree %d source functions, %.1f s" % (len(funcs), sum(map(len, names.by_qual.values())),
                                                                        time.time() - t0), flush=True)
    pairs, how = {}, {}
    outside = set()
    # 1. names
    for a, bf in funcs.items():
        tot["functions"] += 1
        tot["kernel_proper" if a >= KERNEL_START else "prelinked"] += 1
        if bf["name"] is None:
            continue
        tot["seeds"] += 1
        res = linematch.match_named(bf, bf["name"], names, tree, index)
        if res is None:
            tot["seed_unresolved"] += 1
            continue
        pairs[a], how[a] = res, "name"
    tot["seed_matched"] = len(pairs)
    if not quiet:
        print("names: %d seeds, %d resolved to a source function, %.1f s" % (tot["seeds"], len(pairs),
                                                                            time.time() - t0), flush=True)
    # 2. anchors
    taken = {sfunc for _, sfunc, _ in pairs.values()}
    for a, bf in funcs.items():
        if a in pairs:
            continue
        fls = linematch._file_line_anchors(bf["features"])
        if fls:
            tot["fl_functions"] += 1
            tot["fl_anchors"] += len(fls)
            in_tree = 0
            for _, fn, line in fls:
                paths = tree.by_suffix(fn)
                if paths:
                    tot["fl_files_found"] += 1
                    tot["fl_lines_in_file"] += line <= tree.file(paths[0]).nlines
                    in_tree += 1
                else:
                    tot["fl_files_missing"] += 1
            if not in_tree:
                # prelinked kext code (sources are their own projects, not xnu): the anchors are still true
                # addr -> file:line rows, but matching the function against xnu files would be noise
                outside.add(a)
                for addr, fn, line in fls:
                    m.add(shared_row(addr, min(addr + 4, bf["end"]), fn, line))
                continue
        if not anchors:
            continue
        res = linematch.match_function(bf, tree, index=index, taken=taken)
        if res is not None:
            pairs[a], how[a] = res, "anchors"
        tot["anchor_tried"] += 1
        if not quiet and tot["anchor_tried"] % 10000 == 0:
            print("  … anchors %7d tried, %d matched, %.1f s" % (tot["anchor_tried"],
                                                                 sum(1 for h in how.values() if h == "anchors"),
                                                                 time.time() - t0), flush=True)
    tot["outside_tree"] = len(outside)
    # 3. propagation
    if prop:
        got = linematch.propagate(funcs, pairs, names, tree)
        for a in got:
            how[a] = "calls"
        tot["prop_rounds"] = max((r for r, _ in got.values()), default=0)
    # 3b. link order, then propagation again from the new pairs
    sub = {}
    if order:
        got = linematch.link_order(funcs, pairs, tree, index)
        for a, (_, h) in got.items():
            how[a], sub[a] = "order", h
        tot["order_rounds"] = max((r for r, _ in got.values()), default=0)
        if prop and got:
            for a in linematch.propagate(funcs, pairs, names, tree):
                how[a] = "calls"
    # 4. rows + scores
    hit_source, hit_files = set(), Counter()
    sample = []
    for a, (sf, sfunc, anc) in pairs.items():
        h = how[a]
        tot["matched_" + h] += 1
        tot["kp_matched" if a >= KERNEL_START else "pl_matched"] += 1
        for _, _, kind in anc:
            tot["anchor_" + kind] += 1
        hit_source.add((sf.path, sfunc.qualname))
        hit_files[sf.path] += 1
        for r in linematch.rows_for_function(funcs[a], sf, sfunc, anc):
            m.add(r)
        m.functions.append(linematch.Function(
            sfunc.qualname, a, funcs[a]["end"], sf.path, sfunc.first, sfunc.last,
            0.9 if h == "name" else linematch.CONF["file-line"] if any(k == "file-line" for _, _, k in anc)
            else linematch.CONF["string"] if anc else linematch.CONF["function"],
            "%s, %d anchors" % (h, len(anc))))
        n = truth.get(a)
        if n is not None and h != "name":
            ok = agrees(n, sfunc)
            tot["%s_%s" % (h, "agree" if ok else "differ")] += 1
            if h == "order":
                tot["order_%s_%s" % (sub[a], "agree" if ok else "differ")] += 1
            if not ok and len(sample) < 16:
                sample.append((n, "%#x" % a, "%s -> %s" % (h, sfunc.qualname)))
    # what was there to find: named, not a seed, with the name in the tree
    for a, n in truth.items():
        if funcs[a]["name"] is None and names.lookup(n):
            tot["findable"] += 1
            tot["found"] += a in pairs
    if out:
        m.save(out)
    if not quiet:
        print("%.1f s" % (time.time() - t0))
        print("records %(recs)d (%(nohlil)d without HLIL, %(skipped)d skipped, %(errors)d errors)" % tot)
        print("functions %(functions)d (kernel proper %(kernel_proper)d, prelinked %(prelinked)d);"
              " outside the tree %(outside_tree)d" % tot)
        print("matched: by name %(matched_name)d / anchors %(matched_anchors)d / calls %(matched_calls)d"
              " / order %(matched_order)d (kp %(kp_matched)d / pl %(pl_matched)d; %(prop_rounds)d propagation,"
              " %(order_rounds)d order rounds)" % tot)
        print("anchors: file-line %(anchor_file-line)d, string %(anchor_string)d, const %(anchor_const)d,"
              " call %(anchor_call)d" % tot)
        print("file:line anchors: %(fl_functions)d functions, %(fl_anchors)d anchors: file in the tree"
              " %(fl_files_found)d / missing %(fl_files_missing)d, line inside the file %(fl_lines_in_file)d" % tot)
        print("named %d: seeds %d (resolved %d, unresolved %d)%s" % (
            len(truth), tot["seeds"], tot["seed_matched"], tot["seed_unresolved"],
            ", held out %d" % (len(truth) - tot["seeds"]) if holdout else ""))
        print("vs the names: anchors agree %(anchors_agree)d / differ %(anchors_differ)d;"
              " calls agree %(calls_agree)d / differ %(calls_differ)d;"
              " order agree %(order_agree)d / differ %(order_differ)d (by anchors %(order_anchors_agree)d /"
              " %(order_anchors_differ)d, by position %(order_position_agree)d / %(order_position_differ)d)" % tot)
        if holdout:
            print("held out with the name in the tree: %(findable)d, found %(found)d" % tot)
        print("source functions hit: %d in %d files" % (len(hit_source), len(hit_files)))
        for p, k in hit_files.most_common(5):
            print("  %4d  %s" % (k, os.path.relpath(p, xnu)))
        if sample:
            print("disagreeing (sample):")
            for n, a, note in sample:
                print("  %-40s %s  %s" % (n[:40], a, note))
    return tot


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--feats", default=FEATS)
    ap.add_argument("--symbols", default=SYMBOLS)
    ap.add_argument("--xnu", default=XNU)
    ap.add_argument("--out")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--skip", type=int, default=0)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--holdout", action="store_true", help="seed with half of the names, score the other half")
    ap.add_argument("--no-anchors", action="store_true", help="skip the anchor match of unnamed functions")
    ap.add_argument("--no-propagate", action="store_true")
    ap.add_argument("--only", choices=("kp", "pl"), help="kernel proper / prelinked functions only")
    ap.add_argument("--no-order", action="store_true", help="skip the link-order phase")
    ap.add_argument("--no-exclude", action="store_true", help="keep the x86 and user-space source files")
    args = ap.parse_args()
    run(args.feats, args.symbols, args.xnu, args.out, args.limit, args.skip, args.quiet, args.holdout,
        not args.no_anchors, not args.no_propagate, args.only, () if args.no_exclude else XNU_ARM64_EXCLUDE,
        not args.no_order)
