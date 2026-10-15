"""Kernel side of the sloppy line mapping (bncpp-36), offline / REFERENCE ONLY: adapt the BN feature dump
(tests/bn_line_features.py JSONL, taken from the kernel session's kernelcache view) to the matcher's input,
join the names from the kernel symbols file, run the lazy matcher against the xnu tree, and score:

  - function match vs the known names (the symbols file: ground truth for the matcher's choice)
  - __FILE__+__LINE__ anchor self-checks (the file exists in the tree, the line is inside it)
  - the share of binary functions matched at all, and the source functions / files hit

  python3 -I tests/ref_kernel_linemap.py [--limit N] [--skip N] [--out MAP.json] [--quiet]
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


def demangle(names):
    """c++filt a batch of Itanium names, if it is available: {mangled: 'OSObject::release'}"""
    mangled = [n for n in names if n.startswith("_Z")]
    if not mangled:
        return {}
    try:
        p = subprocess.run(["c++filt"], input="\n".join(mangled), capture_output=True, text=True, timeout=60)
        if p.returncode != 0:
            return {}
        return dict(zip(mangled, [l.split("(")[0] for l in p.stdout.splitlines()]))
    except (OSError, subprocess.TimeoutExpired):
        return {}


def name_of(addr, symbols, demangled):
    """the source-side name of a symbol: a demangled C++ qualified name, else the plain name"""
    n = symbols.get(addr)
    if n is None:
        return None
    return demangled.get(n, n)


def bin_funcs(feats_path, symbols, demangled, limit=None, skip=0):
    """the dump's records as matcher input: {"start", "end", "name", "features"} with int addresses; a bl whose
    target carries a symbol becomes a call feature (named callees are anchors); __builtin_ names also match the
    plain source name"""
    stats = {"recs": 0, "nohlil": 0, "skipped": 0, "errors": 0, "bl_named": 0, "builtin": 0}
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
                    if k == "bl":
                        if v:
                            n = name_of(int(v, 16), symbols, demangled)
                            if n is not None:
                                feats.append((int(a, 16), "call", n))
                                stats["bl_named"] += 1
                            else:
                                feats.append((int(a, 16), "bl", None))
                    elif k == "call":
                        feats.append((int(a, 16), "call", v))
                        if v.startswith("__builtin_") and len(v) > 10:  # the plain name is what the source shows
                            feats.append((int(a, 16), "call", v[len("__builtin_"):]))
                            stats["builtin"] += 1
                    else:
                        feats.append((int(a, 16), k, v))
            yield {"start": int(r["start"], 16), "end": int(r["end"], 16),
                   "name": name_of(int(r["start"], 16), symbols, demangled), "features": feats}
    yield stats  # sentinel: the caller cannot know the counts before the stream ends


def run(feats, symbols_path, xnu, out=None, limit=None, skip=0, quiet=False):
    symbols = read_symbols(symbols_path)
    demangled = demangle(set(symbols.values()))
    tree = SourceTree(xnu)
    index = linematch.FileIndex(tree)
    m = LineMap({"name": "kernelcache.iphone10.dec"}, {"name": "xnu-8796.141.3", "root": xnu})
    tot = Counter(dict.fromkeys(
        ("recs", "nohlil", "skipped", "errors", "bl_named", "builtin", "functions", "matched", "unmatched",
         "anchors", "anchor_file-line", "anchor_string", "anchor_const", "anchor_call", "fl_functions",
         "fl_anchors", "fl_files_found", "fl_files_missing", "fl_lines_in_file", "outside_tree",
         "kernel_proper", "prelinked", "kp_matched", "pl_matched", "named", "named_matched", "named_agree",
         "named_differ"), 0))
    t0 = time.time()
    unmatched_named = []
    hit_source = set()
    hit_files = Counter()
    for bf in bin_funcs(feats, symbols, demangled, limit, skip):
        if "recs" in bf:
            tot.update(bf)
            continue
        tot["functions"] += 1
        tot["kernel_proper" if bf["start"] >= KERNEL_START else "prelinked"] += 1
        if not quiet and tot["functions"] % 5000 == 0:
            print("  … %7d functions, %d matched, %.1f s" % (tot["functions"], tot["matched"],
                                                             time.time() - t0), flush=True)
        fls = linematch._file_line_anchors(bf["features"])
        if fls:
            tot["fl_functions"] += 1
            tot["fl_anchors"] += len(fls)
            in_tree = 0
            for _, fn, line in fls:
                paths = tree.by_suffix(fn)
                if paths:
                    tot["fl_files_found"] += 1
                    if line <= tree.file(paths[0]).nlines:
                        tot["fl_lines_in_file"] += 1
                    in_tree += 1
                else:
                    tot["fl_files_missing"] += 1
            if not in_tree:
                # prelinked kext code (sources are their own projects, not xnu): the anchors are still true
                # addr -> file:line rows, but matching the function against xnu files would be noise
                tot["outside_tree"] += 1
                for addr, fn, line in fls:
                    m.add(shared_row(addr, min(addr + 4, bf["end"]), fn, line))
                continue
        if bf["name"] is not None:
            tot["named"] += 1
        res = linematch.match_function(bf, tree, index=index)
        if res is None:
            tot["unmatched"] += 1
            if bf["name"] and len(unmatched_named) < 12:
                unmatched_named.append((bf["name"], "%#x" % bf["start"],
                                        "fl" if fls else ("str" if any(k == "str" for _, k, _ in bf["features"])
                                                         else "none")))
            continue
        sf, sfunc, anchors = res
        tot["matched"] += 1
        tot["kp_matched" if bf["start"] >= KERNEL_START else "pl_matched"] += 1
        tot["anchors"] += len(anchors)
        for _, _, kind in anchors:
            tot["anchor_" + kind] += 1
        hit_source.add((sf.path, sfunc.qualname))
        hit_files[sf.path] += 1
        if bf["name"] is not None:
            tot["named_matched"] += 1
            n = bf["name"]
            agree = (sfunc.qualname == n) or ("(" not in n and sfunc.qualname.split("::")[-1] == n.split("::")[-1])
            tot["named_agree" if agree else "named_differ"] += 1
            if not agree and len(unmatched_named) < 12:
                unmatched_named.append((bf["name"], "%#x" % bf["start"], "-> %s" % sfunc.qualname))
        for r in linematch.rows_for_function(bf, sf, sfunc, anchors):
            m.add(r)
        m.functions.append(linematch.Function(
            sfunc.qualname, bf["start"], bf["end"], sf.path, sfunc.first, sfunc.last,
            linematch.CONF["file-line"] if any(k == "file-line" for _, _, k in anchors)
            else linematch.CONF["string"] if anchors else linematch.CONF["function"],
            "%d anchors" % len(anchors)))
    if out:
        m.save(out)
    if not quiet:
        print("records %(recs)d (%(nohlil)d without HLIL, %(skipped)d skipped, %(errors)d errors)"
              % dict(tot))
        print("functions %(functions)d (kernel proper %(kernel_proper)d, prelinked %(prelinked)d):"
              " matched %(matched)d (kp %(kp_matched)d / pl %(pl_matched)d), unmatched %(unmatched)d,"
              " outside the tree %(outside_tree)d" % dict(tot))
        print("anchors: %(anchors)d (file-line %(anchor_file-line)d, string %(anchor_string)d,"
              " const %(anchor_const)d, call %(anchor_call)d)" % dict(tot))
        print("file:line anchors: %(fl_functions)d functions, %(fl_anchors)d anchors: file in the tree"
              " %(fl_files_found)d / missing %(fl_files_missing)d, line inside the file %(fl_lines_in_file)d"
              % dict(tot))
        print("named: %(named)d functions carry a symbol; of those matched %(named_matched)d:"
              " name agrees %(named_agree)d / differs %(named_differ)d" % dict(tot))
        print("source functions hit: %d in %d files; top:" % (len(hit_source), len(hit_files)))
        for p, n in hit_files.most_common(8):
            print("  %4d  %s" % (n, os.path.relpath(p, xnu)))
        if unmatched_named:
            print("named but unmatched / disagreeing (sample):")
            for n, a, note in unmatched_named:
                print("  %-40s %s  %s" % (n, a, note))
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
    args = ap.parse_args()
    run(args.feats, args.symbols, args.xnu, args.out, args.limit, args.skip, args.quiet)
