"""A function's LSDA on Mach-O (Apple): the compact unwind table (__TEXT,__unwind_info).

Apple's linker emits no __eh_frame for most functions -- CFI is converted to compact unwind
(__unwind_info) and the LSDA bytes stay in __TEXT,__gcc_except_tab. The route to a function's
LSDA is therefore the compact unwind table, not an FDE augmentation: the top-level index splits
__TEXT into ranges; each range's entry points at a second-level page (function -> encoding) and
at an LSDA index array (function offset -> LSDA offset). An encoding carries the personality
index (2 bits) and the has-LSDA flag; the LSDA index arrays are the address source.
(A function whose encoding is UNWIND_X86_64/ARM64_MODE_DWARF keeps an FDE in __eh_frame instead;
not handled yet -- the suite has none.)

Format: mach-o/compact_unwind_encoding.h (LLVM libunwind; linked on wiki references.md).
Pure Python (struct only), offline-testable -- no Binary Ninja import.
"""
import struct

IS_NOT_FUNCTION_START = 0x80000000
HAS_LSDA = 0x40000000
PERSONALITY_MASK = 0x30000000
PERSONALITY_SHIFT = 28
SECOND_LEVEL_REGULAR = 2
SECOND_LEVEL_COMPRESSED = 3


class FunctionUnwind:
    """one entry of the compact unwind table"""

    __slots__ = ("addr", "encoding", "personality", "lsda")

    def __init__(self, addr, encoding, personality, lsda):
        self.addr = addr                # function start (an entry covers up to the next entry)
        self.encoding = encoding        # compact_unwind_encoding_t
        self.personality = personality  # personality routine address slot (or None)
        self.lsda = lsda                # LSDA address in __gcc_except_tab (or None)

    def __repr__(self):
        return "FunctionUnwind(%#x, encoding=%#010x, lsda=%s)" % (
            self.addr, self.encoding, "%#x" % self.lsda if self.lsda is not None else None)


def functions(macho):
    """every entry of the compact unwind table, in address order ([] without __unwind_info)"""
    sec = macho.section("__TEXT", "__unwind_info")
    if sec is None:
        return []
    data = macho.section_data(sec)
    base = macho.text_base
    version, common_off, common_count, pers_off, pers_count, index_off, index_count = \
        struct.unpack_from("<7I", data, 0)
    if version != 1:
        raise ValueError("unsupported __unwind_info version %d" % version)
    common = struct.unpack_from("<%dI" % common_count, data, common_off)
    personalities = struct.unpack_from("<%dI" % pers_count, data, pers_off)  # offsets of pointer slots
    index = [struct.unpack_from("<3I", data, index_off + 12 * i) for i in range(index_count)]

    # the LSDA index arrays are consecutive; range i's array ends where range i+1's begins
    # (the last index entry is a sentinel whose lsda offset marks the end of all arrays)
    lsda = {}
    for i in range(index_count - 1):
        start, end = index[i][2], index[i + 1][2]
        for off in range(start, end, 8):
            fofs, lofs = struct.unpack_from("<II", data, off)
            lsda[fofs] = base + lofs

    out = []
    for i in range(index_count - 1):  # the last entry is the sentinel (end of __text)
        first, page, _lsda = index[i]
        if not page:
            continue
        (kind,) = struct.unpack_from("<I", data, page)
        if kind == SECOND_LEVEL_REGULAR:
            _k, entry_off, count = struct.unpack_from("<IHH", data, page)
            for j in range(count):
                fofs, enc = struct.unpack_from("<II", data, page + entry_off + 8 * j)
                out.append((fofs, enc))
        elif kind == SECOND_LEVEL_COMPRESSED:
            _k, entry_off, count, enc_off, enc_count = struct.unpack_from("<IHHHH", data, page)
            local = struct.unpack_from("<%dI" % enc_count, data, page + enc_off)
            for j in range(count):
                (e,) = struct.unpack_from("<I", data, page + entry_off + 4 * j)
                ei = e >> 24
                enc = common[ei] if ei < common_count else local[ei - common_count]
                out.append((first + (e & 0xFFFFFF), enc))
        else:
            raise ValueError("unknown second-level page kind %d" % kind)

    result = []
    for fofs, enc in sorted(out):
        p = (enc & PERSONALITY_MASK) >> PERSONALITY_SHIFT
        result.append(FunctionUnwind(
            base + fofs, enc,
            base + personalities[p - 1] if p else None,
            lsda.get(fofs) if enc & HAS_LSDA else None))
    return result


def lsda_of(macho, addr):
    """the LSDA address of the function starting at addr, or None"""
    for f in functions(macho):
        if f.addr == addr:
            return f.lsda
    return None
