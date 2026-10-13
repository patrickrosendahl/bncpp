"""The image interface of the decoders (cpp/unwind_info.py, cpp/lsda.py), backed by a Binary Ninja view.

Binary Ninja is the source of truth for everything format-specific -- sections, segments, symbols, imports;
the decoders only interpret bytes. cpp/macho.py implements the same interface from the file itself, as an
offline reference (cross-checks, bug reports), never as the product.

  read(addr, n) -> bytes            section_range(name) -> (start, end) | None
  section_range_at(addr) -> (start, end) | None        segment_start(addr) -> int
  pointer_target(slot) -> name | address               symbol_name(addr) -> name | None
"""
from binaryninja import SymbolType

_IMPORTS = (SymbolType.ImportAddressSymbol, SymbolType.ImportedDataSymbol, SymbolType.ImportedFunctionSymbol,
            SymbolType.ExternalSymbol)


class BNImage:
    def __init__(self, bv):
        self.bv = bv
        self._sections = {}  # start -> (end, bytes): each section is read from BN once, then sliced here

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
            return s.full_name
        ptr = self.bv.read_pointer(slot)
        t = self.bv.get_symbol_at(ptr)
        return t.full_name if t is not None else ptr

    def symbol_name(self, addr):
        f = self.bv.get_function_at(addr)
        if f is not None:
            return f.symbol.full_name
        s = self.bv.get_symbol_at(addr)
        return s.full_name if s is not None else None
