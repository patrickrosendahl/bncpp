"""Minimal Mach-O reader -- REFERENCE ONLY: Binary Ninja is the source of truth (cpp/bnimage.py).

Implements the decoders' image interface (see cpp/bnimage.py) from the file itself, for offline
cross-checks of what the plugin gets from BN and as evidence for bug reports. A thin 64-bit
little-endian image (x86_64 / arm64; a universal binary is reduced to one slice with `arch`).
Pure Python (struct only), no Binary Ninja import.
"""
import struct

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x80000022
INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000
CPU_TYPES = {"x86_64": 0x01000007, "arm64": 0x0100000C}


class Section:
    __slots__ = ("segname", "name", "addr", "size", "offset", "flags", "reserved1", "reserved2")

    def __init__(self, segname, name, addr, size, offset, flags, reserved1, reserved2):
        self.segname, self.name = segname, name
        self.addr, self.size, self.offset = addr, size, offset
        self.flags, self.reserved1, self.reserved2 = flags, reserved1, reserved2

    def __repr__(self):
        return "Section(%s,%s %#x+%#x)" % (self.segname, self.name, self.addr, self.size)


class MachO:
    def __init__(self, path, arch=None):
        with open(path, "rb") as f:
            image = f.read()
        self.image = self._slice(image, arch)
        self.sections = []
        self.segments = {}  # segname -> (vmaddr, vmsize, fileoff, filesize)
        self._segment_order = []  # vmaddr per LC_SEGMENT_64, in load-command order
        self.symbols = {}   # address -> name (first defined symbol at each address)
        self._symtab = None
        self._dysymtab = None
        self._dyld_info = None
        self._binds = None
        self._load_commands()

    @staticmethod
    def _slice(image, arch):
        (magic,) = struct.unpack_from(">I", image, 0)
        if magic != FAT_MAGIC:
            return image
        (nfat,) = struct.unpack_from(">I", image, 4)
        want = CPU_TYPES.get(arch or "x86_64")
        for i in range(nfat):
            cputype, _sub, offset, size, _align = struct.unpack_from(">iiIII", image, 8 + 20 * i)
            if cputype == want:
                return image[offset:offset + size]
        raise ValueError("no %s slice" % arch)

    def _load_commands(self):
        magic, self.cputype, _sub, _ftype, ncmds, _size, _flags, _res = \
            struct.unpack_from("<IiiIIIII", self.image, 0)
        if magic != MH_MAGIC_64:
            raise ValueError("not a 64-bit little-endian Mach-O (magic %#x)" % magic)
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.image, off)
            if cmd == LC_SEGMENT_64:
                segname = _cstr(self.image[off + 8:off + 24])
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", self.image, off + 24)
                (nsects,) = struct.unpack_from("<I", self.image, off + 64)
                self.segments[segname] = (vmaddr, vmsize, fileoff, filesize)
                self._segment_order.append(vmaddr)
                s = off + 72  # sizeof(segment_command_64)
                for _ in range(nsects):
                    name = _cstr(self.image[s:s + 16])
                    seg = _cstr(self.image[s + 16:s + 32])
                    addr, size, offset, _al, _rel, _nrel, flags, r1, r2 = \
                        struct.unpack_from("<QQIIIIIII", self.image, s + 32)
                    self.sections.append(Section(seg, name, addr, size, offset, flags, r1, r2))
                    s += 80  # sizeof(section_64)
            elif cmd == LC_SYMTAB:
                self._symtab = struct.unpack_from("<IIII", self.image, off + 8)
            elif cmd == LC_DYSYMTAB:
                # ilocalsym..nundefsym (6), tocoff..nextrefsyms (4), indirectsymoff, nindirectsyms, ...
                fields = struct.unpack_from("<18I", self.image, off + 8)
                self._dysymtab = {"indirectsymoff": fields[12], "nindirectsyms": fields[13]}
            elif cmd in (LC_DYLD_INFO, LC_DYLD_INFO_ONLY):
                # rebase, bind, weak_bind, lazy_bind, export: (off, size) each
                self._dyld_info = struct.unpack_from("<10I", self.image, off + 8)
            off += cmdsize
        self._names = self._read_symtab()

    def _read_symtab(self):
        """symbol index -> (name, value, n_type); fills self.symbols for defined symbols"""
        names = []
        if not self._symtab:
            return names
        symoff, nsyms, stroff, strsize = self._symtab
        strtab = self.image[stroff:stroff + strsize]
        for i in range(nsyms):
            n_strx, n_type, _sect, _desc, value = struct.unpack_from("<IBBHQ", self.image, symoff + 16 * i)
            name = _cstr(strtab[n_strx:n_strx + 1024])
            names.append((name, value, n_type))
            if name and value and not n_type & 0xE0 and n_type & 0x0E == 0x0E:  # N_SECT, not stab
                self.symbols.setdefault(value, name)
        return names

    # -- queries ----------------------------------------------------------------

    def section(self, segname, name):
        for s in self.sections:
            if s.segname == segname and s.name == name:
                return s
        return None

    def section_at(self, addr):
        for s in self.sections:
            if s.addr <= addr < s.addr + s.size:
                return s
        return None

    def read(self, addr, size):
        """bytes at a virtual address (zero-fill sections read as zeros)"""
        s = self.section_at(addr)
        if s is None:
            raise ValueError("address %#x is in no section" % addr)
        if not s.offset:
            return bytes(size)
        o = s.offset + addr - s.addr
        return self.image[o:o + size]

    def section_data(self, s):
        return self.image[s.offset:s.offset + s.size] if s.offset else bytes(s.size)

    @property
    def text_base(self):
        return self.segments["__TEXT"][0]

    # -- the image interface (cpp/bnimage.py) ---------------------------------------

    def section_range(self, name):
        for sec in self.sections:
            if sec.name == name:
                return sec.addr, sec.addr + sec.size
        return None

    def section_range_at(self, addr):
        sec = self.section_at(addr)
        return (sec.addr, sec.addr + sec.size) if sec is not None else None

    def segment_start(self, addr):
        for vmaddr, vmsize, _fo, _fs in self.segments.values():
            if vmaddr <= addr < vmaddr + vmsize:
                return vmaddr
        raise ValueError("address %#x is in no segment" % addr)

    def symbol_name(self, addr):
        return self.symbols.get(addr)

    def symbol_at(self, addr):
        """(start, name) of the nearest defined symbol at or below addr"""
        best = None
        for a, n in self.symbols.items():
            if a <= addr and (best is None or a > best[0]):
                best = (a, n)
        return best

    def pointer_target(self, addr):
        """what the pointer slot at addr refers to: a symbol name for an import or local symbol, else
        the raw target address. Import slots (__got, __la_symbol_ptr, ...) are named through the
        indirect symbol table, which works for both classic bind info and chained fixups."""
        s = self.section_at(addr)
        if s is not None and self._dysymtab and s.flags & 0xFF in (0x6, 0x7):  # NON_LAZY / LAZY_SYMBOL_POINTERS
            i = s.reserved1 + (addr - s.addr) // 8
            (isym,) = struct.unpack_from("<I", self.image, self._dysymtab["indirectsymoff"] + 4 * i)
            if not isym & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS):
                return self._names[isym][0]
        (raw,) = struct.unpack_from("<Q", self.read(addr, 8))
        target = self._untag(raw)
        return self.symbols.get(target, target)

    @property
    def binds(self):
        """{slot address: (symbol, addend)} from the classic dyld bind opcodes (bind + weak bind + lazy
        bind); empty for chained-fixup images. With classic dyld info a bound slot holds no usable
        value in the file, so this is the only way to name it."""
        if self._binds is None:
            self._binds = {}
            if self._dyld_info:
                d = self._dyld_info
                for off, size in ((d[2], d[3]), (d[4], d[5]), (d[6], d[7])):
                    if size:
                        self._run_binds(self.image[off:off + size])
        return self._binds

    def _run_binds(self, ops):
        """interpret one bind opcode stream (mach-o/loader.h BIND_OPCODE_*)"""
        segs = [s for s in self._segment_order]
        sym, addend, seg, offset, p = None, 0, 0, 0, 0

        def uleb():
            nonlocal p
            v = shift = 0
            while True:
                b = ops[p]
                p += 1
                v |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    return v

        def sleb():
            nonlocal p
            v = shift = 0
            while True:
                b = ops[p]
                p += 1
                v |= (b & 0x7F) << shift
                shift += 7
                if not b & 0x80:
                    return v - (1 << shift) if b & 0x40 else v

        def bind():
            self._binds[segs[seg] + offset] = (sym, addend)

        while p < len(ops):
            b = ops[p]
            p += 1
            op, imm = b & 0xF0, b & 0x0F
            if op == 0x00:  # DONE (lazy streams separate entries with DONE: keep going)
                continue
            elif op in (0x10, 0x30):  # SET_DYLIB_ORDINAL_IMM / _SPECIAL_IMM
                pass
            elif op == 0x20:  # SET_DYLIB_ORDINAL_ULEB
                uleb()
            elif op == 0x40:  # SET_SYMBOL_TRAILING_FLAGS_IMM
                end = ops.index(b"\0", p)
                sym = ops[p:end].decode("utf8", "replace")
                p = end + 1
            elif op == 0x50:  # SET_TYPE_IMM
                pass
            elif op == 0x60:  # SET_ADDEND_SLEB
                addend = sleb()
            elif op == 0x70:  # SET_SEGMENT_AND_OFFSET_ULEB
                seg, offset = imm, uleb()
            elif op == 0x80:  # ADD_ADDR_ULEB
                offset = (offset + uleb()) & 0xFFFFFFFFFFFFFFFF
            elif op == 0x90:  # DO_BIND
                bind()
                offset += 8
            elif op == 0xA0:  # DO_BIND_ADD_ADDR_ULEB
                bind()
                offset += 8 + uleb()
            elif op == 0xB0:  # DO_BIND_ADD_ADDR_IMM_SCALED
                bind()
                offset += 8 + imm * 8
            elif op == 0xC0:  # DO_BIND_ULEB_TIMES_SKIPPING_ULEB
                count, skip = uleb(), uleb()
                for _ in range(count):
                    bind()
                    offset += 8 + skip
            elif op == 0xD0:  # THREADED (chained binds of an older format): not supported
                raise NotImplementedError("BIND_OPCODE_THREADED")
            else:
                raise ValueError("unknown bind opcode %#x" % b)

    @staticmethod
    def _untag(raw):
        """a rebase target from a raw pointer: plain, or a DYLD_CHAINED_PTR_64 rebase
        (target in the low 36 bits, high8 at bit 36)"""
        if raw >> 63:  # a bind in a fixup chain: no static target
            return None
        if raw >> 36:
            return (raw & 0xFFFFFFFFF) | ((raw >> 36) & 0xFF) << 56
        return raw


def _cstr(b):
    return b.split(b"\0", 1)[0].decode("utf8", "replace")
