"""Itanium C++ RTTI and vtables from an image: typeinfo objects, their names and bases, the vtables that use them.

  typeinfo    [vptr -> __cxxabiv1::__{class,si_class,vmi_class}_type_info's vtable + 16][name -> "N3foo3barE"]
              si: + [base typeinfo]   vmi: + [u32 flags][u32 count] + count x [base typeinfo][offset_flags]
              offset_flags: bit 0 virtual, bit 1 public, >> 8 = offset of the base (vbase: vtable offset)
  vtable      [offset_to_top (0 primary, < 0 secondary)][typeinfo] -> address point: virtual function slots

The vptr of a typeinfo is a bind to the C++ runtime. With classic dyld info the file holds only the bind's
addend (0x10) there, and Binary Ninja 6.1 keeps no relocation for binds with an addend (bncpp-21) -- so where
the image has no bound symbol for the vptr, the kind is recognised from the layout: vptr word 0x10, a name
pointer to a string, used (pointed at from data, or from code where the image knows code references), si if
the next word points at another typeinfo, vmi if it is a small flags/count pair followed by that many bases;
a small flags word followed by a typeinfo pointer is a __pointer_type_info and skipped. An enum typeinfo looks
like a class typeinfo ([vptr][name]) and is not told apart.

Name sources: the type name string (mangled without the _ZTS prefix, or an obfuscated hex hash), and binds that
keep the real mangled name even where the string was hashed: (weak) binds of references to the typeinfo
(__ZTI...) and of its name pointer (__ZTS..., reported as the matching __ZTI name).

Pure Python, no Binary Ninja import: reads through an image (cpp/bnimage.py in BN; cpp/macho.py offline, as a
reference only). Image methods used: read, section_range, section_range_at, data_sections, bound_symbols.
"""
import struct

KINDS = {"__ZTVN10__cxxabiv117__class_type_infoE": "class",
         "__ZTVN10__cxxabiv120__si_class_type_infoE": "si",
         "__ZTVN10__cxxabiv121__vmi_class_type_infoE": "vmi"}
_OTHER_TYPEINFO = ("__ZTVN10__cxxabiv116__enum_type_infoE", "__ZTVN10__cxxabiv119__pointer_type_infoE",
                   "__ZTVN10__cxxabiv117__array_type_infoE", "__ZTVN10__cxxabiv120__function_type_infoE",
                   "__ZTVN10__cxxabiv129__pointer_to_member_type_infoE",
                   "__ZTVN10__cxxabiv123__fundamental_type_infoE")
VPTR_ADDEND = 0x10
_HEX = set("0123456789abcdef")


class TypeInfo:
    __slots__ = ("addr", "kind", "name", "bases", "bind_names", "vtables", "kind_from")

    def __init__(self, addr, kind, name, kind_from):
        self.addr = addr
        self.kind = kind            # class / si / vmi
        self.name = name            # the name string (mangled, minus _ZTS) or None
        self.bases = []             # [(typeinfo address | imported __ZTI name, offset_flags or None)]
        self.bind_names = []        # real names from binds of references to this typeinfo (__ZTI...)
        self.vtables = []           # [VTable], primary first
        self.kind_from = kind_from  # "bind" (the vptr's bound symbol) or "layout"

    @property
    def name_kind(self):
        n = self.name
        if not n:
            return "none"
        if not set(n.replace("_", "")) <= _HEX:
            return "mangled"
        # all hex: a hash, unless it is exactly a length-prefixed source name ("3abc" = class abc)
        digits = len(n) - len(n.lstrip("0123456789"))
        return "mangled" if digits and n[0] != "0" and int(n[:digits]) == len(n) - digits else "hash"

    def __repr__(self):
        return "TypeInfo(%#x %s %r, %d vtables)" % (self.addr, self.kind, self.name, len(self.vtables))


class VTable:
    __slots__ = ("addr", "offset_to_top", "slots")

    def __init__(self, addr, offset_to_top, slots):
        self.addr = addr                    # address point (first virtual function slot)
        self.offset_to_top = offset_to_top  # 0: primary; < 0: secondary (a base subobject at -offset)
        self.slots = slots                  # [code address | "pure" | imported symbol name]


class _Words:
    """the image's data sections, read once, as 8-byte words"""

    def __init__(self, img):
        self.secs = []  # (start, end, bytes)
        for _name, start, end in img.data_sections():
            self.secs.append((start, end, img.read(start, end - start)))

    def q(self, addr):
        for start, end, data in self.secs:
            if start <= addr <= end - 8:
                return struct.unpack_from("<Q", data, addr - start)[0]
        return None

    def items(self):
        for start, end, data in self.secs:
            for i in range(0, len(data) - 7, 8):
                yield start + i, struct.unpack_from("<Q", data, i)[0]


def _cstring(img, addr, limit=512):
    r = img.section_range_at(addr)
    if r is None:
        return None
    b = img.read(addr, min(limit, r[1] - addr))
    end = b.find(b"\0")
    if end <= 0:
        return None
    s = b[:end]
    if any(c < 0x20 or c > 0x7E for c in s):
        return None
    return s.decode("ascii")


def scan(img):
    """{typeinfo address: TypeInfo} for every class typeinfo (class / si / vmi) in the image's data"""
    words = _Words(img)
    binds = img.bound_symbols()
    lossy = getattr(img, "lost_binds", False)  # the image may miss binds (BN 6.1): zero slots may be imports
    text = img.section_range("__text")
    data = [(s, e) for _n, s, e in img.data_sections()]

    def in_data(v):
        return v is not None and any(s <= v < e for s, e in data)

    def is_code(v):
        return v is not None and text is not None and text[0] <= v < text[1]

    # 1. candidates: a bound vptr to a type_info vtable, or (no bind known) the vptr word 0x10 + a name string
    cands = {}  # addr -> (kind or None, name, kind_from)
    for addr, v in words.items():
        sym = binds.get(addr)
        if sym in KINDS:
            np = words.q(addr + 8)
            cands[addr] = (KINDS[sym], _cstring(img, np) if np else None, "bind")
        elif sym is None and v == VPTR_ADDEND:
            np = words.q(addr + 8)
            nsym = binds.get(addr + 8)
            name = _cstring(img, np) if np is not None and not in_data(np) else None
            if name or (nsym is not None and nsym.startswith("__ZTS")):
                cands[addr] = (None, name, "layout")
    # a layout candidate must be used: pointed at from data (a vtable, a base, an import slot) or from code
    # (throw / catch sites; an image without code references -- the offline one -- has all vptr binds anyway)
    referenced = set(v for _a, v in words.items() if v in cands)
    code_refs = getattr(img, "has_code_refs", None)
    cands = {a: c for a, c in cands.items()
             if c[2] == "bind" or a in referenced or (code_refs is not None and code_refs(a))}

    # 2. kinds and bases; a base is a typeinfo address here, or the bound name of an imported one (__ZTI...)
    def base_at(a):
        v = words.q(a)
        if v in cands:
            return v  # also a weak bind that resolves to this image's typeinfo
        sym = binds.get(a)
        return sym if sym is not None and sym.startswith("__ZTI") else None

    def slot_like(a):
        """a virtual function slot: code, or a bound import other than a typeinfo"""
        sym = binds.get(a)
        if sym is not None:
            return not (sym.startswith("__ZTI") or sym in KINDS or sym in _OTHER_TYPEINFO)
        return is_code(words.q(a))

    def starts_object(a):
        """a typeinfo, or a vtable ([offset_to_top][typeinfo]), begins at a"""
        if a in cands:
            return True
        ott = words.q(a)
        return ott is not None and (ott == 0 or ott >> 63 and ott > (1 << 64) - 0x10000) \
            and words.q(a + 8) in cands

    types = {}
    for addr, (kind, name, frm) in cands.items():
        bases = []
        w2 = words.q(addr + 16)
        if kind in (None, "vmi") and w2 is not None:
            flags, count = w2 & 0xFFFFFFFF, w2 >> 32
            if (kind == "vmi" or flags <= 3) and 0 < count <= 64:
                entries = [(base_at(addr + 24 + 16 * i), words.q(addr + 32 + 16 * i)) for i in range(count)]
                if kind == "vmi" or all(b is not None for b, _of in entries):
                    kind, bases = "vmi", entries
        if kind is None and w2 is not None and w2 <= 0x1F and base_at(addr + 24) is not None \
                and not slot_like(addr + 32):
            continue  # __pointer_type_info: [flags][pointee typeinfo] (a vtable here would go on with slots)
        if kind in (None, "si") and not bases:
            b = base_at(addr + 16)
            if kind == "si" or b is not None:
                kind, bases = "si", [(b if b is not None else w2, None)]
            elif w2 == 0 and not starts_object(addr + 16) and starts_object(addr + 24):
                kind, bases = "si", [("?", None)]  # an imported base whose bind the image lost (BN 6.1)
        t = types[addr] = TypeInfo(addr, kind or "class", name, frm)
        t.bases = bases

    # 3. real names from binds of references (weak binds of __ZTI... resolved to this image's typeinfo)
    for slot, sym in binds.items():
        if sym.startswith("__ZTI"):
            v = words.q(slot)
            if v in types and sym not in types[v].bind_names:
                types[v].bind_names.append(sym)
        elif sym.startswith("__ZTS") and slot - 8 in types:  # the name pointer itself is a (weak) bind
            t = types[slot - 8]
            if "__ZTI" + sym[5:] not in t.bind_names:
                t.bind_names.append("__ZTI" + sym[5:])
    for t in types.values():
        t.bind_names.sort()

    # 4. vtables: [offset_to_top][typeinfo] followed by virtual function slots
    for addr, v in words.items():
        if v not in types:
            continue
        ott = words.q(addr - 8)
        if ott is None:
            continue
        ott = ott - (1 << 64) if ott >> 63 else ott
        if not -0x10000 < ott <= 0:
            continue
        slots, j = [], addr + 8
        while True:
            w = words.q(j)
            sym = binds.get(j)
            if w is None or starts_object(j):
                break
            if sym is not None:
                if "pure_virtual" in sym:
                    slots.append("pure")
                elif sym.startswith("__ZTI") or sym in KINDS or sym in _OTHER_TYPEINFO:
                    break  # the next object
                else:
                    slots.append(sym)  # an imported virtual (inherited from a library class)
            elif is_code(w):
                slots.append(w)
            elif w == 0 and lossy:
                # imported virtuals whose binds the image lost (BN 6.1): a run of zero words, taken as slots if
                # the vtable goes on after it. At the end of a vtable a lost import and alignment padding before
                # the next object look alike, so a trailing run ends the vtable (it may miss imported slots).
                k = j
                while words.q(k) == 0 and binds.get(k) is None and k - j < 512:
                    k += 8
                if k - j >= 512 or starts_object(k) or starts_object(k - 8) or not slot_like(k):
                    break
                slots.extend(["import ?"] * ((k - j) // 8))
                j = k
                continue
            else:
                break
            j += 8
        slots = _cut_member_pointers(slots)
        if slots:
            types[v].vtables.append(VTable(addr + 8, ott, slots))
    for t in types.values():
        t.vtables.sort(key=lambda vt: (vt.offset_to_top != 0, -vt.offset_to_top, vt.addr))
    return types


def _cut_member_pointers(slots, pairs=4):
    """end a vtable where an array of member function pointers ({function, adjustment 0} pairs) follows it: at
    the first of at least `pairs` single lost-import slots that alternate with real ones (a real vtable can
    alternate too, e.g. basic_filebuf over basic_streambuf's imported virtuals, but not for long). The function
    before the first zero stays a slot, as where the image has every bind and the scan stops at the zero."""
    for i in range(1, len(slots) - 2 * pairs + 1):
        if all(slots[i + 2 * p] == "import ?" and slots[i + 2 * p - 1] != "import ?" for p in range(pairs)) \
                and slots[i + 2 * pairs - 1] != "import ?":
            return slots[:i]
    return slots


def format_scan(types, function_name=None):
    """the scan as text, one block per typeinfo (sorted by address); function_name(addr) -> name or None"""
    def slot(s):
        if isinstance(s, int):
            n = function_name(s) if function_name else None
            return "%#x %s" % (s, n) if n else "%#x" % s
        return s

    out = []
    for addr in sorted(types):
        t = types[addr]
        out.append("typeinfo %#x  %-5s %s %s%s" % (
            addr, t.kind, t.name_kind, t.name or "-",
            "  bind " + ", ".join(t.bind_names) if t.bind_names else ""))
        for b, of in t.bases:
            if isinstance(b, str):
                base = "import %s" % b  # "?" = imported, name unknown
            else:
                bt = types.get(b)
                base = "%#x %s" % (b or 0, bt.name if bt is not None and bt.name else "?")
            out.append("  base %s%s" % (base, "  offset_flags %#x" % of if of is not None else ""))
        for vt in t.vtables:
            out.append("  vtable %#x  offset_to_top %d  %d slots" % (vt.addr, vt.offset_to_top, len(vt.slots)))
            for i, s in enumerate(vt.slots):
                out.append("    [%d] %s" % (i, slot(s)))
    return out
