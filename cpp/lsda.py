"""Decode an Itanium LSDA: the exception table of one function (__gcc_except_tab / .gcc_except_table).

Layout (libstdc++ eh_personality.cc: parse_lsda_header, the personality's call-site and action
loops -- linked on wiki references.md):

  header      u8 lpstart_enc [encoded LPStart, default: function start]
              u8 ttype_enc   [uleb offset -> TType, the END of the type table]
              u8 cs_enc      uleb length  -> action table = first byte after the call-site table
  call sites  (start, length, landing_pad: cs_enc; action: uleb) until the action table; start is
              relative to the function, landing_pad to LPStart (0 = none: the call site may unwind
              straight through), action 0 = cleanup only (no record), else 1 + offset of the
              first action record in the action table
  actions     record = (sleb ar_filter, sleb ar_disp); the next record of a chain is at
              address_of(ar_disp) + ar_disp, ar_disp 0 ends it. ar_filter > 0: catch type number
              ar_filter (entry ar_filter of the type table, 0 entry = catch (...)); 0: cleanup;
              < 0: exception specification (uleb type numbers at TType - ar_filter - 1, 0-ended)
  types       entry i at TType - i * size(ttype_enc), read with ttype_enc; DW_EH_PE_indirect =
              the value is the address of a pointer slot (on Mach-O: __got) holding the typeinfo

Pure Python -- no Binary Ninja import. `decode` works on bare bytes; `parse_function` / `parse_all`
find the LSDAs and name typeinfo slots through an image (cpp/bnimage.py in BN; cpp/macho.py offline,
as a reference only).
"""
import struct

OMIT = 0xFF
ABSPTR, ULEB128, UDATA2, UDATA4, UDATA8 = 0x00, 0x01, 0x02, 0x03, 0x04
SLEB128, SDATA2, SDATA4, SDATA8 = 0x09, 0x0A, 0x0B, 0x0C
PCREL, TEXTREL, DATAREL, FUNCREL, ALIGNED = 0x10, 0x20, 0x30, 0x40, 0x50
INDIRECT = 0x80

_FIXED = {ABSPTR: "<Q", UDATA2: "<H", UDATA4: "<I", UDATA8: "<Q", SDATA2: "<h", SDATA4: "<i", SDATA8: "<q"}


def read_uleb(data, p):
    result = shift = 0
    while True:
        b = data[p]
        p += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return result, p


def read_sleb(data, p):
    result = shift = 0
    while True:
        b = data[p]
        p += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            if b & 0x40:
                result -= 1 << shift
            return result, p


def encoded_size(enc):
    fmt = _FIXED.get(enc & 0x0F)
    if fmt is None:
        raise ValueError("DW_EH_PE %#x has no fixed size" % enc)
    return struct.calcsize(fmt)


def read_encoded(data, p, enc, base):
    """read_encoded_value (unwind-pe.h) at data[p]; base = address of data[0].

    Returns (value, indirect, next p). pcrel values come back absolute; indirect is
    returned as a flag (the caller dereferences: it knows the image)."""
    if enc == OMIT:
        return None, False, p
    fmt_kind = enc & 0x0F
    if fmt_kind == ULEB128:
        v, q = read_uleb(data, p)
    elif fmt_kind == SLEB128:
        v, q = read_sleb(data, p)
    elif fmt_kind in _FIXED:
        fmt = _FIXED[fmt_kind]
        (v,) = struct.unpack_from(fmt, data, p)
        q = p + struct.calcsize(fmt)
    else:
        raise ValueError("unsupported DW_EH_PE format %#x" % enc)
    app = enc & 0x70
    if v == 0:
        return 0, False, q  # read_encoded_value_with_base: a zero value stays zero (NULL), no base
    if app == PCREL:
        v = (base + p + v) & 0xFFFFFFFFFFFFFFFF
    elif app not in (0, ALIGNED):
        # textrel / datarel / funcrel need context the LSDA does not carry (unused by clang/gcc here)
        raise ValueError("unsupported DW_EH_PE application %#x" % enc)
    return v, bool(enc & INDIRECT), q


class Clause:
    """one entry of a call site's action chain, in the order the personality tries them"""

    __slots__ = ("kind", "type_index", "type")

    CATCH, CLEANUP, SPEC = "catch", "cleanup", "spec"

    def __init__(self, kind, type_index=None, type=None):
        self.kind = kind              # catch / cleanup / spec
        self.type_index = type_index  # ar_filter (catch: > 0; spec: < 0)
        self.type = type              # catch: typeinfo (name or address), None = catch (...);
                                      # spec: [typeinfo, ...]

    def __repr__(self):
        if self.kind == self.CATCH:
            return "catch(%s)" % (self.type if self.type is not None else "...")
        if self.kind == self.SPEC:
            return "throw(%s)" % ", ".join(map(str, self.type))
        return "cleanup"


class CallSite:
    __slots__ = ("start", "end", "landing_pad", "action", "clauses")

    def __init__(self, start, end, landing_pad, action, clauses):
        self.start, self.end = start, end  # [start, end) in the function
        self.landing_pad = landing_pad     # address, or None: unwinding goes straight through
        self.action = action               # raw action field (0 = cleanup only / none)
        self.clauses = clauses             # [Clause]; [] with a landing pad = cleanup only

    def __repr__(self):
        return "CallSite(%#x..%#x -> %s %s)" % (
            self.start, self.end, "%#x" % self.landing_pad if self.landing_pad else "unwind",
            self.clauses or ("[cleanup]" if self.landing_pad else "[]"))


class LSDA:
    def __init__(self, addr, func_start, lp_start, ttype_enc, ttype_end, call_sites, types, size):
        self.addr = addr              # address of the LSDA
        self.func_start = func_start
        self.lp_start = lp_start
        self.ttype_enc = ttype_enc
        self.ttype_end = ttype_end    # TType (the table's end), None if no type table
        self.call_sites = call_sites  # [CallSite], table order (sorted by start)
        self.types = types            # {type number: typeinfo}, every number referenced
        self.size = size              # bytes covered, header through the last type entry

    def __repr__(self):
        return "LSDA(%#x for %#x: %d call sites, %d types)" % (
            self.addr, self.func_start, len(self.call_sites), len(self.types))


def decode(data, addr, func_start, deref=None):
    """decode the LSDA in data (data[0] is at address addr) of the function at func_start.

    deref(slot_address) -> typeinfo resolves DW_EH_PE_indirect type entries (the address of
    a pointer slot); without it the slot address itself is returned."""
    p = 0
    lp_enc = data[p]
    p += 1
    lp_start, _ind, p = read_encoded(data, p, lp_enc, addr)
    if lp_start is None:
        lp_start = func_start
    ttype_enc = data[p]
    p += 1
    ttype_end = None
    if ttype_enc != OMIT:
        off, p = read_uleb(data, p)
        ttype_end = addr + p + off
    cs_enc = data[p]
    p += 1
    length, p = read_uleb(data, p)
    actions = p + length  # offset of the action table in data

    raw = []
    while p < actions:
        start, _i, p = read_encoded(data, p, cs_enc, addr)
        size, _i, p = read_encoded(data, p, cs_enc, addr)
        lp, _i, p = read_encoded(data, p, cs_enc, addr)
        action, p = read_uleb(data, p)
        raw.append((start, size, lp, action))
    end = actions

    types = {}
    tsize = encoded_size(ttype_enc) if ttype_enc != OMIT else 0

    def type_entry(i):
        if i not in types:
            o = ttype_end - addr - i * tsize
            v, ind, _ = read_encoded(data, o, ttype_enc, addr)
            if v == 0:
                types[i] = None  # catch (...)
            else:
                types[i] = deref(v) if ind and deref else v
        return types[i]

    def spec(filter_):
        out, q = [], ttype_end - addr - filter_ - 1
        while True:
            n, q = read_uleb(data, q)
            if not n:
                return out
            out.append(type_entry(n))

    call_sites = []
    for start, size, lp, action in raw:
        clauses = []
        if action:
            q = actions + action - 1
            while True:
                ar_filter, q = read_sleb(data, q)
                disp_at = q
                ar_disp, q = read_sleb(data, q)
                end = max(end, q)
                if ar_filter > 0:
                    clauses.append(Clause(Clause.CATCH, ar_filter, type_entry(ar_filter)))
                elif ar_filter == 0:
                    clauses.append(Clause(Clause.CLEANUP))
                else:
                    clauses.append(Clause(Clause.SPEC, ar_filter, spec(ar_filter)))
                if not ar_disp:
                    break
                q = disp_at + ar_disp
        call_sites.append(CallSite(func_start + start, func_start + start + size,
                                   lp_start + lp if lp else None, action, clauses))

    size = (ttype_end - addr) if ttype_end is not None else end
    return LSDA(addr, func_start, lp_start, ttype_enc, ttype_end, call_sites, types, size)


def _decode_at(img, lsda, func_start):
    _start, end = img.section_range_at(lsda)
    return decode(img.read(lsda, end - lsda), lsda, func_start, img.pointer_target)


def parse_function(img, func_start):
    """the decoded LSDA of the function at func_start, or None"""
    from . import unwind_info
    lsda = unwind_info.lsda_of(img, func_start)
    return _decode_at(img, lsda, func_start) if lsda is not None else None


def parse_all(img):
    """{function start: LSDA} for every function with an LSDA"""
    from . import unwind_info
    return {f.addr: _decode_at(img, f.lsda, f.addr) for f in unwind_info.functions(img) if f.lsda is not None}


def format_lsda(l, name=None, base=0):
    """the LSDA as text (the suite's .lsda reference): code offsets relative to the function start,
    the LSDA's own address relative to the image base (BN rebases a dylib, the file does not)"""
    f = l.func_start

    def rel(a):
        return "+%#x" % (a - f)

    out = ["%s  lsda base+%#x  lpstart %s  %d call sites" % (
        name or "%#x" % f, l.addr - base, rel(l.lp_start), len(l.call_sites))]
    for cs in l.call_sites:
        if cs.landing_pad is None:
            what = "unwind"
        else:
            what = "lp %-6s %s" % (rel(cs.landing_pad),
                                   ", ".join(map(str, cs.clauses)) if cs.clauses else "cleanup")
        out.append("  %-6s .. %-6s %s" % (rel(cs.start), rel(cs.end), what))
    return out


LOST = "  in no function: "  # a .lsda line after a table: code of its call sites BN shows in no function (bncpp-182)


def format_lost(l, starts):
    """the LOST line for format_lsda's table l (none when nothing is lost; the offline reference has none)"""
    return [LOST + " ".join("+%#x" % (a - l.func_start) for a in starts)] if starts else []
