"""Ground truth for the line maps (bncpp-40): a real DWARF line table -> shared/linemap.py's format.

REFERENCE ONLY (like tests/ref_class_scan.py): BN 6.1 exposes no line tables, so this reads them with the
toolchain's dwarfdump (llvm-dwarfdump) at test time. Input: a dSYM bundle or a binary with DWARF.
  python3 -I tests/ref_dwarf_lines.py X.dylib.dSYM [-o X.linemap.json] [--arch arm64]
Rows: one per line-table row up to the next row of the sequence (end_sequence ends it), file:line exact, src
'dwarf', conf 1; line 0 rows kept (compiler-made code, the scorer skips them). Functions: DW_TAG_subprogram with
low_pc / high_pc and their decl_file / decl_line; the last line of a function = the highest line of its rows.
"""
import os, re, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from shared.linemap import Function, LineMap, Row  # noqa: E402


def _dwarfdump(args):
    return subprocess.run(["xcrun", "dwarfdump"] + args, check=True, capture_output=True, text=True).stdout


def read(path, arch=None):
    """a LineMap of the DWARF in path (dSYM bundle or a binary)"""
    a = ["--arch", arch] if arch else []
    m = LineMap({"name": os.path.basename(path.rstrip("/")).replace(".dSYM", ""), "arch": arch, "base": 0})
    uu = re.search(r"UUID: ([0-9A-F-]+) \((\w+)\)", _dwarfdump(["--uuid"] + a + [path]))
    if uu:
        m.binary["uuid"], m.binary["arch"] = uu.group(1), uu.group(2)
    # line tables: per table the file names (DWARF 5: index 0 = the CU's file), then the rows
    dirs, files, prev = {}, {}, None
    for line in _dwarfdump(["--debug-line"] + a + [path]).splitlines():
        if line.startswith("debug_line["):
            dirs, files, prev = {}, {}, None
            continue
        md = re.match(r'include_directories\[\s*(\d+)\] = "(.*)"', line)
        if md:
            dirs[int(md.group(1))] = md.group(2)
            continue
        mf = re.match(r"file_names\[\s*(\d+)\]:", line)
        if mf:
            cur = int(mf.group(1))
            files[cur] = ["", 0]
            continue
        mn = re.match(r'\s+name: "(.*)"', line)
        if mn and files:
            files[max(files)][0] = mn.group(1)
            continue
        mi = re.match(r"\s+dir_index: (\d+)", line)
        if mi and files:
            files[max(files)][1] = int(mi.group(1))
            continue
        mr = re.match(r"0x([0-9a-f]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\d+\s+\d+\s+\d+\s*(.*)", line)
        if mr:
            addr, ln, fi, flags = int(mr.group(1), 16), int(mr.group(2)), int(mr.group(4)), mr.group(5)
            if prev is not None and addr > prev[0]:
                m.add(Row(prev[0], addr, prev[2], prev[1], prev[1], 1.0, "dwarf"))
            if "end_sequence" in flags:
                prev = None
                continue
            name, di = files.get(fi, ("?", 0))
            path_ = name if name.startswith("/") else os.path.join(dirs.get(di, ""), name)
            prev = (addr, ln, path_)
    # functions
    cur = None
    for line in _dwarfdump(["--debug-info"] + a + [path]).splitlines():
        if "DW_TAG_" in line:
            if cur is not None and "low" in cur and "high" in cur:
                m.functions.append(Function(cur.get("name", "?"), cur["low"], cur["high"], cur.get("file"),
                                            cur.get("line")))
            cur = {} if "DW_TAG_subprogram" in line else None
            continue
        if cur is None:
            continue
        kv = re.match(r"\s+DW_AT_(\w+)\s+\((.*)\)\s*$", line)
        if not kv:
            continue
        k, v = kv.groups()
        if k == "low_pc":
            cur["low"] = int(v, 16)
        elif k == "high_pc":
            cur["high"] = int(v, 16) if v.startswith("0x") and len(v) > 12 else cur.get("low", 0) + int(v, 16)
        elif k == "name":
            cur["name"] = v.strip('"')
        elif k == "linkage_name" and "name" not in cur:
            cur["name"] = v.strip('"')
        elif k == "decl_file":
            cur["file"] = v.strip('"')
        elif k == "decl_line":
            cur["line"] = int(v)
    if cur is not None and "low" in cur and "high" in cur:
        m.functions.append(Function(cur.get("name", "?"), cur["low"], cur["high"], cur.get("file"), cur.get("line")))
    for f in m.functions:  # the last line: the highest line the rows inside give
        lines = [r.last for r in m.rows() if f.start <= r.start < f.end and r.first > 0 and r.file == f.file]
        f.first = min([f.first] + lines) if f.first is not None and lines else f.first
        f.last = max(lines) if lines else f.first
    m.functions.sort(key=lambda f: f.start)
    return m


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("-o", "--out")
    ap.add_argument("--arch")
    args = ap.parse_args()
    lm = read(args.path, args.arch)
    if args.out:
        lm.save(args.out)
    print("%d functions, %d rows" % (len(lm.functions), len(lm.rows())))
    for f in lm.functions:
        print("  %s" % f)
