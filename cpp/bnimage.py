"""The image interface of the decoders (cpp/unwind_info.py, cpp/lsda.py), backed by a Binary Ninja view.

Binary Ninja is the source of truth for everything format-specific -- sections, segments, symbols, imports;
the decoders only interpret bytes. cpp/macho.py implements the same interface from the file itself, as an
offline reference (cross-checks, bug reports), never as the product.

  read(addr, n) -> bytes            section_range(name) -> (start, end) | None
  section_range_at(addr) -> (start, end) | None        segment_start(addr) -> int
  pointer_target(slot) -> name | address               symbol_name(addr) -> name | None
  data_sections() -> [(name, start, end)]              bound_symbols() -> {slot: raw symbol name}
  has_code_refs(addr) -> bool (optional: images that know code references)
  symbol_keys(name) -> [raw name | address] (optional: the closure veto resolves the LSDA's catch type names)

Hooks of the class modules (cpp/rtti_names.py, cpp/rtti_types.py): demangle, call_targets, symbol_at.
"""
from binaryninja import MediumLevelILOperation, QualifiedName, SectionSemantics, SymbolType, demangle_gnu3

_IMPORTS = (SymbolType.ImportAddressSymbol, SymbolType.ImportedDataSymbol, SymbolType.ImportedFunctionSymbol,
            SymbolType.ExternalSymbol)


def mlil_offset(e):
    """the value of an MLIL constant used as an offset, else None: BN gives the 0x30 in [rax + 0x30] as MLIL_CONST in
    one function and MLIL_CONST_PTR in another (bncpp-115); a CONST_PTR that is an address in the view is a table
    ([rdx + 0x100859630]), not an offset"""
    if e.operation == MediumLevelILOperation.MLIL_CONST:
        return e.constant
    if e.operation == MediumLevelILOperation.MLIL_CONST_PTR and not e.function.source_function.view.is_valid_offset(e.constant):
        return e.constant
    return None


class BNImage:
    lost_binds = True  # BN 6.1 resolves Mach-O binds through the nlist names: renamed / missing ones are dropped (bncpp-25)

    def __init__(self, bv):
        self.bv = bv
        self._sections = {}  # start -> (end, bytes): each section is read from BN once, then sliced here
        self._bound = None

    def read(self, addr, n):
        secs = self.bv.get_sections_at(addr)
        if not secs or addr + n > secs[0].end:
            return self.bv.read(addr, n)  # outside a section, or straddling two: ask BN directly
        s = secs[0]
        cached = self._sections.get(s.start)
        if cached is None:
            cached = self._sections[s.start] = self.bv.read(s.start, s.end - s.start)
        return cached[addr - s.start:addr - s.start + n]

    def section_range(self, name):
        s = self.bv.sections.get(name)
        return (s.start, s.end) if s is not None else None

    def section_range_at(self, addr):
        secs = self.bv.get_sections_at(addr)
        return (secs[0].start, secs[0].end) if secs else None

    def segment_start(self, addr):
        return self.bv.get_segment_at(addr).start

    def pointer_target(self, slot):
        """an import slot's symbol name (BN names __got / IAT slots), else what the pointer points at"""
        s = self.bv.get_symbol_at(slot)
        if s is not None and s.type in _IMPORTS:
            if not _typeinfo(s):  # a bind an obfuscator renamed (SynthV's hashed nlist names, bncpp-25): the local
                try:  # typeinfo it points to names it, as typeinfo_arg does for a throw (bncpp-116, bncpp-170)
                    t = self.bv.get_symbol_at(self.bv.read_pointer(slot))
                except Exception:
                    t = None
                if _typeinfo(t):
                    return t.full_name
            return s.full_name
        ptr = self.bv.read_pointer(slot)
        t = self.bv.get_symbol_at(ptr)
        return t.full_name if t is not None else ptr

    def symbol_keys(self, name):
        """the symbols BN shows as name: their raw names, and the addresses of the non-import ones (resolves the
        LSDA's catch type names: a local typeinfo, or a weak bind's import slot named __ZTI...)"""
        out = []
        for s in self.bv.get_symbols_by_name(name):
            out.append(s.raw_name)
            if s.type not in _IMPORTS:
                out.append(s.address)
        return out

    def symbol_name(self, addr):
        f = self.bv.get_function_at(addr)
        if f is not None:
            return f.symbol.full_name
        s = self.bv.get_symbol_at(addr)
        return s.full_name if s is not None else None

    def data_sections(self):
        """[(name, start, end)] of the sections in writable segments (not BN's synthetic .extern etc.)"""
        out = []
        for s in sorted(self.bv.sections.values(), key=lambda s: s.start):
            seg = self.bv.get_segment_at(s.start)
            if seg is not None and seg.writable and seg.data_length and \
                    s.semantics != SectionSemantics.ExternalSectionSemantics:
                out.append((s.name, s.start, s.end))
        return out

    def bound_symbols(self):
        """{slot: raw symbol name} of the relocations BN keeps with a symbol (binds; BN 6.1 drops binds whose
        symbol is missing from the nlist, e.g. hashed by an obfuscator -- see cpp/rtti.py, bncpp-25)"""
        if self._bound is None:
            self._bound = {}
            for start, _end in self.bv.relocation_ranges:
                for r in self.bv.relocations_at(start):
                    sym = r.symbol
                    if sym is not None:
                        self._bound[start] = sym.raw_name
        return self._bound

    def has_code_refs(self, addr):
        return any(True for _ in self.bv.get_code_refs(addr))

    # hooks of cpp/rtti_names.py / cpp/rtti_types.py

    def demangle(self, mangled):
        """'__ZTS4Node' -> 'typeinfo name for Node' (BN's spelling), None if BN can't demangle it"""
        try:
            _ty, parts = demangle_gnu3(self.bv.arch, mangled)
        except Exception:
            return None
        return str(QualifiedName(parts)) if parts else None

    def call_targets(self, addr):
        """per call site of the function at addr (tail calls included): a local function's address, or an
        import's raw name; None if there is no function there"""
        f = self.bv.get_function_at(addr)
        if f is None:
            return None
        out = []
        for site in f.call_sites:
            for t in self.bv.get_callees(site.address, f, site.arch):
                s = self.bv.get_symbol_at(t)
                out.append(s.raw_name if s is not None and s.type in _IMPORTS else t)
        return out

    def symbol_at(self, addr):
        """(full name, user-defined?) of the symbol at addr, or None"""
        s = self.bv.get_symbol_at(addr)
        return (s.full_name, not s.auto) if s is not None else None


def _typeinfo(sym):
    """sym names a typeinfo (__ZTI..., BN's typeinfo_for_...)"""
    return sym is not None and (sym.raw_name.startswith("__ZTI") or sym.full_name.startswith("typeinfo_for_"))
