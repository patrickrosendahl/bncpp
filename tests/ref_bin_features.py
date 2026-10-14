"""Binary side of the sloppy line mapping, REFERENCE ONLY (bncpp-36): the features a function shows, from
otool -tV's disassembly -- so the matcher can be scored on the suite without Binary Ninja. The real extractor
reads the same from BN (functions, HLIL / MLIL constants, string references, call targets).

Per function: start, end, name (None with names=False: a stripped binary, as BN would show sub_X), the
instruction addresses, and the features [(addr, kind, value)]:
  str    a string the instruction references (otool: 'literal pool for: "..."')
  call   a call to a named target (imports / stubs; internal targets only when names are kept)
  num    an immediate of mov / cmp style instructions, other than 0 and 1 (not address arithmetic)
  bl     a call site without a name (marks the end of an argument window)
  python3 -I tests/ref_bin_features.py X.dylib [--arch arm64] [--names]
"""
import os, re, subprocess, sys


def _unescape(s):
    return s.encode("latin-1", "backslashreplace").decode("unicode_escape", "replace")


_NUM_MN = re.compile(r"^(mov|movz|movn|orr|cmp|cmn|tst|ccmp|movl|movq|movw|movb|cmpl|cmpq|cmpw|cmpb|testl|testq|"
                     r"movabsq|pushq|subs|adds)$")


def read(path, arch=None, names=False):
    a = ["-arch", arch] if arch else []
    text = subprocess.run(["otool", "-tV"] + a + [path], check=True, capture_output=True, text=True,
                          errors="replace").stdout
    funcs, cur = [], None
    for line in text.splitlines():
        lab = re.match(r"^(\S.*):$", line)
        if lab and not line.startswith("(") and "section" not in line:
            if cur is not None:
                funcs.append(cur)
            nm = lab.group(1)
            cur = {"name": nm[1:] if nm.startswith("_") else nm, "start": None, "end": None, "insns": [],
                   "features": []}
            continue
        m = re.match(r"^([0-9a-f]{8,16})\s+(\S+)\s*(.*)$", line)
        if m is None or cur is None:
            continue
        addr, mn, ops = int(m.group(1), 16), m.group(2), m.group(3)
        if cur["start"] is None:
            cur["start"] = addr
        cur["insns"].append(addr)
        lp = re.search(r'literal pool for: "(.*)"', ops)
        if lp:
            cur["features"].append((addr, "str", _unescape(lp.group(1))))
            continue
        stub = re.search(r"symbol stub for: _?(\S+)", ops)
        if mn in ("bl", "callq", "call", "b", "jmp", "jmpq") and stub:
            cur["features"].append((addr, "call", stub.group(1)))
            continue
        if mn in ("bl", "callq", "call"):
            tgt = re.match(r"_(\S+)", ops.strip())
            if tgt and names:
                cur["features"].append((addr, "call", tgt.group(1)))
            else:
                cur["features"].append((addr, "bl", None))
            continue
        if _NUM_MN.match(mn) and "[" not in ops and "(%" not in ops.split(",")[0]:
            for imm in re.findall(r"[#$](-?0x[0-9a-f]+|-?\d+)\b", ops):
                v = int(imm, 0)
                if v not in (0, 1, -1):
                    cur["features"].append((addr, "num", v))
    if cur is not None:
        funcs.append(cur)
    funcs = [f for f in funcs if f["start"] is not None]
    funcs.sort(key=lambda f: f["start"])
    for i, f in enumerate(funcs):
        last = f["insns"][-1]
        f["end"] = last + 4 if (arch or "").startswith("arm") or _is_arm(path, arch) else last + 1
        if i + 1 < len(funcs):
            f["end"] = max(f["end"], min(funcs[i + 1]["start"], f["end"] + 16))
        if not names:
            f["name"] = None
    return funcs


def _is_arm(path, arch):
    if arch:
        return arch.startswith("arm")
    out = subprocess.run(["lipo", "-archs", path], capture_output=True, text=True).stdout
    return out.strip().startswith("arm")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--arch")
    ap.add_argument("--names", action="store_true")
    args = ap.parse_args()
    for f in read(args.path, args.arch, args.names):
        print("%s %#x-%#x %d insns" % (f["name"], f["start"], f["end"], len(f["insns"])))
        for addr, k, v in f["features"]:
            print("    %#x %s %r" % (addr, k, v))
