# shared with binary-jvm: not yet (new here, bncpp-38); keep language-neutral
"""dSYM export of a line map (bncpp-38): lldb, atos, dwarfdump and symbolizers show file:line for a binary
built without debug info. Lossy: one line per row (the range's first line), rows below a confidence threshold
stay in the line map only.

Container: a Mach-O MH_DSYM with the binary's LC_UUID (lldb and atos match a dSYM by it), copies of its
segments with no file contents (the addresses lldb slides by), and a __DWARF segment mapped after them with __debug_abbrev,
__debug_info, __debug_line, __debug_str, __debug_ranges and __debug_aranges (DWARF 4). One compile unit per
source file: a function belongs to its source file's unit, a row to the unit of the function around it (else of
its own file); a unit's line table names every file its rows use. DW_TAG_subprogram per function with a name.

  write(linemap, binary_path, out_dsym, min_conf=0.5, arch=None) -> {"units", "functions", "rows", "skipped"}
  python3 -I shared/dsym.py MAP.json BINARY OUT.dSYM [--min-conf 0.5] [--arch arm64]
Pure Python (struct only), no Binary Ninja import, no toolchain.
"""
import os
import struct

MH_MAGIC_64, FAT_MAGIC = 0xFEEDFACF, 0xCAFEBABE
MH_DSYM = 0xA
LC_SEGMENT_64, LC_UUID, LC_SYMTAB = 0x19, 0x1B, 0x2
CPU_TYPES = {"x86_64": 0x01000007, "arm64": 0x0100000C}

# DWARF 4
DW_TAG_compile_unit, DW_TAG_subprogram = 0x11, 0x2E
DW_AT_name, DW_AT_stmt_list, DW_AT_low_pc, DW_AT_high_pc = 0x03, 0x10, 0x11, 0x12
DW_AT_language, DW_AT_comp_dir, DW_AT_producer, DW_AT_ranges = 0x13, 0x1B, 0x25, 0x55
DW_AT_decl_file, DW_AT_decl_line, DW_AT_external = 0x3A, 0x3B, 0x3F
DW_FORM_addr, DW_FORM_data2, DW_FORM_data4, DW_FORM_strp = 0x01, 0x05, 0x06, 0x0E
DW_FORM_sec_offset, DW_FORM_flag_present = 0x17, 0x19
DW_LANG_C99, DW_LANG_C_plus_plus = 0x0C, 0x04
DW_LNS_copy, DW_LNS_advance_pc, DW_LNS_advance_line, DW_LNS_set_file = 1, 2, 3, 4
DW_LNE_end_sequence, DW_LNE_set_address = 1, 2
PRODUCER = "bncpp line map (bncpp-38)"
CPP_EXTS = (".cpp", ".cc", ".cxx", ".mm", ".hpp", ".h++")


def uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v == 0 and not b & 0x40 or v == -1 and b & 0x40:
            out.append(b)
            return bytes(out)
        out.append(b | 0x80)


def read_image(path, arch=None):
    """(cputype, cpusubtype, uuid bytes, [segment_command_64 bytes]) of a thin slice"""
    with open(path, "rb") as fh:
        image = fh.read()
    if struct.unpack_from(">I", image, 0)[0] == FAT_MAGIC:
        want = CPU_TYPES.get(arch or "arm64")
        for i in range(struct.unpack_from(">I", image, 4)[0]):
            ct, _, off, size, _ = struct.unpack_from(">iiIII", image, 8 + 20 * i)
            if ct == want:
                image = image[off:off + size]
                break
        else:
            raise ValueError("no %s slice in %s" % (arch, path))
    magic, cputype, cpusub, _, ncmds = struct.unpack_from("<IiiII", image, 0)
    if magic != MH_MAGIC_64:
        raise ValueError("not a 64-bit little-endian Mach-O: %s" % path)
    uuid, segs, off = None, [], 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from("<II", image, off)
        if cmd == LC_UUID:
            uuid = image[off + 8:off + 24]
        elif cmd == LC_SEGMENT_64:
            segs.append(image[off:off + size])
        off += size
    if uuid is None:
        raise ValueError("no LC_UUID in %s: lldb could not match a dSYM to it" % path)
    return cputype, cpusub, uuid, segs


def _empty_segment(raw):
    """a copy of a binary's segment_command_64 without file contents (as dsymutil writes them)"""
    b = bytearray(raw)
    struct.pack_into("<QQ", b, 40, 0, 0)               # fileoff, filesize
    nsects = struct.unpack_from("<I", b, 64)[0]
    for i in range(nsects):
        s = 72 + 80 * i
        struct.pack_into("<I", b, s + 48, 0)           # offset
        struct.pack_into("<II", b, s + 56, 0, 0)       # reloff, nreloc
    return bytes(b)


class _Strings:
    def __init__(self):
        self.data, self.at = bytearray(b"\0"), {}

    def __call__(self, s):
        if s not in self.at:
            self.at[s] = len(self.data)
            self.data += s.encode("utf-8") + b"\0"
        return self.at[s]


def _units(linemap, min_conf, inside=None):
    """{cu file: {"functions": [Function], "rows": [Row]}}; inside(start, end): the range lies in the binary
    (rows and functions outside it are dropped and counted as skipped)"""
    inside = inside or (lambda a, b: True)
    units = {}
    funcs = sorted((f for f in linemap.functions if f.file is not None and inside(f.start, f.end)),
                   key=lambda f: f.start)
    for f in funcs:
        units.setdefault(f.file, {"functions": [], "rows": []})["functions"].append(f)
    skipped = 0
    for r in linemap.rows():
        if r.conf < min_conf or r.first <= 0 or not inside(r.start, r.end):
            skipped += 1
            continue
        f = linemap.function_at(r.start)
        cu = f.file if f is not None and f.file is not None else r.file
        units.setdefault(cu, {"functions": [], "rows": []})["rows"].append(r)
    return units, skipped


def _line_program(cu_file, rows):
    """a DWARF 4 line-number program: header (one file table) + one sequence per run of adjacent rows"""
    files = [cu_file] + sorted({r.file for r in rows} - {cu_file})
    fidx = {f: i + 1 for i, f in enumerate(files)}
    prog = bytearray()
    prev_end, cur_addr, line, fcur = None, None, 1, 1
    for r in rows:
        if prev_end is not None and r.start != prev_end:
            prog += bytes([DW_LNS_advance_pc]) + uleb(prev_end - cur_addr)
            prog += b"\0" + uleb(1) + bytes([DW_LNE_end_sequence])
            prev_end, line, fcur = None, 1, 1
        if prev_end is None:
            prog += b"\0" + uleb(9) + bytes([DW_LNE_set_address]) + struct.pack("<Q", r.start)
        else:
            prog += bytes([DW_LNS_advance_pc]) + uleb(r.start - cur_addr)
        if fidx[r.file] != fcur:
            fcur = fidx[r.file]
            prog += bytes([DW_LNS_set_file]) + uleb(fcur)
        if r.first != line:
            prog += bytes([DW_LNS_advance_line]) + sleb(r.first - line)
            line = r.first
        prog += bytes([DW_LNS_copy])
        cur_addr, prev_end = r.start, r.end
    if prev_end is not None:
        prog += bytes([DW_LNS_advance_pc]) + uleb(prev_end - cur_addr)
        prog += b"\0" + uleb(1) + bytes([DW_LNE_end_sequence])
    # header after header_length: min_inst_length, max_ops, default_is_stmt, line_base, line_range, opcode_base,
    # standard_opcode_lengths, include_directories (none), file_names (absolute paths, dir 0)
    hdr = struct.pack("<BBBbBB", 1, 1, 1, -5, 14, 13) + bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]) + b"\0"
    for f in files:
        hdr += f.encode("utf-8") + b"\0" + uleb(0) + uleb(0) + uleb(0)
    hdr += b"\0"
    body = struct.pack("<H", 4) + struct.pack("<I", len(hdr)) + hdr + prog
    return struct.pack("<I", len(body)) + body


def _abbrev():
    def entry(code, tag, children, attrs):
        out = uleb(code) + uleb(tag) + bytes([children])
        for a, f in attrs:
            out += uleb(a) + uleb(f)
        return out + b"\0\0"
    return (entry(1, DW_TAG_compile_unit, 1, [(DW_AT_producer, DW_FORM_strp), (DW_AT_language, DW_FORM_data2),
                                              (DW_AT_name, DW_FORM_strp), (DW_AT_comp_dir, DW_FORM_strp),
                                              (DW_AT_stmt_list, DW_FORM_sec_offset), (DW_AT_low_pc, DW_FORM_addr),
                                              (DW_AT_ranges, DW_FORM_sec_offset)])
            + entry(2, DW_TAG_subprogram, 0, [(DW_AT_name, DW_FORM_strp), (DW_AT_low_pc, DW_FORM_addr),
                                              (DW_AT_high_pc, DW_FORM_data4), (DW_AT_decl_file, DW_FORM_data4),
                                              (DW_AT_decl_line, DW_FORM_data4), (DW_AT_external, DW_FORM_flag_present)])
            + b"\0")


def _merge(spans):
    out = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return out


def dwarf_sections(linemap, min_conf=0.5, comp_dir="/", inside=None):
    """{section name: bytes} of the DWARF for a line map, and the counts"""
    units, skipped = _units(linemap, min_conf, inside)
    # a function's end in the map is its highest block, which can lie past the next function's start: DWARF
    # wants disjoint subprograms, so each ends at the next start
    starts = sorted({f.start for f in linemap.functions})
    nxt = dict(zip(starts, starts[1:]))
    strs = _Strings()
    info, line, ranges, aranges = bytearray(), bytearray(), bytearray(), bytearray()
    n_funcs = n_rows = 0
    for cu_file in sorted(units):
        u = units[cu_file]
        rows = u["rows"]
        ends = {id(f): min(f.end, nxt.get(f.start, f.end)) for f in u["functions"]}
        spans = _merge([(f.start, ends[id(f)]) for f in u["functions"]] + [(r.start, r.end) for r in rows])
        if not spans:
            continue
        stmt = len(line)
        line += _line_program(cu_file, rows)
        rng = len(ranges)
        for a, b in spans:
            ranges += struct.pack("<QQ", a, b)
        ranges += struct.pack("<QQ", 0, 0)
        lang = DW_LANG_C_plus_plus if cu_file.endswith(CPP_EXTS) else DW_LANG_C99
        die = bytearray(uleb(1) + struct.pack("<IHIIIQI", strs(PRODUCER), lang, strs(cu_file), strs(comp_dir),
                                              stmt, 0, rng))
        for f in u["functions"]:
            if ends[id(f)] <= f.start:
                continue
            die += uleb(2) + struct.pack("<IQIII", strs(f.name), f.start, ends[id(f)] - f.start, 1,
                                         max(f.first or 0, 0))
            n_funcs += 1
        die += b"\0"
        cu_off = len(info)
        info += struct.pack("<IHIB", 7 + len(die), 4, 0, 8) + die
        # aranges: header 12 bytes + padding to 16 (2 * address size), then (address, length) pairs
        body = struct.pack("<HIBB", 2, cu_off, 8, 0) + b"\0" * 4
        for a, b in spans:
            body += struct.pack("<QQ", a, b - a)
        body += struct.pack("<QQ", 0, 0)
        aranges += struct.pack("<I", len(body)) + body
        n_rows += len(rows)
    secs = {"__debug_abbrev": _abbrev(), "__debug_info": bytes(info), "__debug_line": bytes(line),
            "__debug_str": bytes(strs.data), "__debug_ranges": bytes(ranges), "__debug_aranges": bytes(aranges)}
    return secs, {"units": sum(1 for u in units.values() if u["functions"] or u["rows"]), "functions": n_funcs,
                  "rows": n_rows, "skipped": skipped}


def write(linemap, binary_path, out_dsym, min_conf=0.5, arch=None):
    """write out_dsym (a .dSYM bundle) for binary_path from a line map; returns the counts"""
    cputype, cpusub, uuid, segs = read_image(binary_path, arch)
    spans = [struct.unpack_from("<QQ", s, 24) for s in segs]

    def inside(a, b):
        return any(va <= a and b <= va + vs for va, vs in spans)
    secs, counts = dwarf_sections(linemap, min_conf, inside=inside)
    order = ["__debug_line", "__debug_aranges", "__debug_info", "__debug_abbrev", "__debug_str", "__debug_ranges"]
    seg_copies = [_empty_segment(s) for s in segs if s[8:24].rstrip(b"\0") != b"__LINKEDIT"]
    dwarf_cmd_size = 72 + 80 * len(order)
    cmds_size = 24 + 24 + sum(len(s) for s in seg_copies) + dwarf_cmd_size
    off = (32 + cmds_size + 0xFFF) & ~0xFFF
    # __DWARF is mapped after the binary's highest segment, as dsymutil does: loaders that read sections through
    # their addresses (BN's DWARF import) find nothing in a segment of vmsize 0
    vmaddr = (max(va + vs for va, vs in spans) + 0xFFF) & ~0xFFF
    data, sects = bytearray(), b""
    for name in order:
        body = secs[name]
        sects += struct.pack("<16s16sQQIIIIIIII", name.encode(), b"__DWARF", vmaddr + len(data), len(body),
                             off + len(data), 0, 0, 0, 0, 0, 0, 0)
        data += body
    dwarf = struct.pack("<II16sQQQQiiII", LC_SEGMENT_64, dwarf_cmd_size, b"__DWARF", vmaddr,
                        (len(data) + 0xFFF) & ~0xFFF, off, len(data), 7, 3, len(order), 0) + sects
    cmds = struct.pack("<II16s", LC_UUID, 24, uuid) + struct.pack("<IIIIII", LC_SYMTAB, 24, 0, 0, 0, 0) \
        + b"".join(seg_copies) + dwarf
    ncmds = 2 + len(seg_copies) + 1
    image = struct.pack("<IiiIIIII", MH_MAGIC_64, cputype, cpusub, MH_DSYM, ncmds, len(cmds), 0, 0) + cmds
    image += b"\0" * (off - len(image)) + data
    res = os.path.join(out_dsym, "Contents", "Resources", "DWARF")
    os.makedirs(res, exist_ok=True)
    name = os.path.basename(binary_path)
    with open(os.path.join(res, name), "wb") as fh:
        fh.write(image)
    with open(os.path.join(out_dsym, "Contents", "Info.plist"), "w") as fh:
        fh.write(_PLIST % name)
    return counts


_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key><string>English</string>
	<key>CFBundleIdentifier</key><string>com.apple.xcode.dsym.%s</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundlePackageType</key><string>dSYM</string>
	<key>CFBundleSignature</key><string>????</string>
	<key>CFBundleShortVersionString</key><string>1.0</string>
	<key>CFBundleVersion</key><string>1</string>
</dict>
</plist>
"""


if __name__ == "__main__":
    import argparse, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from shared.linemap import LineMap
    ap = argparse.ArgumentParser()
    ap.add_argument("map")
    ap.add_argument("binary")
    ap.add_argument("out")
    ap.add_argument("--min-conf", type=float, default=0.5)
    ap.add_argument("--arch")
    args = ap.parse_args()
    print(write(LineMap.load(args.map), args.binary, args.out, args.min_conf, args.arch))
