"""Landing pads Binary Ninja did not make functions (bncpp-4).

BN never follows the unwind edge from a call site to its landing pad: a pad is either split off as a function of
its own (sub_...) or, often for catch (...) and cleanup pads, in no function at all -- its handler code is then in
no view (wiki eh-in-hlil.md). The LSDA names every pad, so a function is created at each one that has none; the
try/catch rendering (bncpp-6) finds the handler as the function at the pad's address.

Creating functions changes the view: in the plugin it is a command, never automatic (another session's database
changes only through its own lane: tests/bn_landing_pads.py dry run + review first, then APPLY).

Terminate guards (bncpp-52): a catch (...) pad that only calls clang's ___clang_call_terminate ('push; call
___cxa_begin_catch; call std::terminate'). Where std::terminate's import name is hashed, BN thinks the helper
returns and runs the guards one after another into one function. The helper is recognised by its body (callees:
___cxa_begin_catch and exactly one other), and it and its terminate callee get a __noreturn user type -- before
the pads are created, so the guards become pads of their own.
"""
from . import lsda as _lsda
from .bnimage import BNImage


class Pad:
    __slots__ = ("addr", "owner", "kinds")

    def __init__(self, addr, owner, kinds):
        self.addr = addr      # the landing pad
        self.owner = owner    # start of the function whose LSDA lists it
        self.kinds = kinds    # "catch(T), catch(...)", "cleanup"


def pads(bv):
    """every landing pad of every LSDA: [Pad], by address (a pad shared by several call sites once)"""
    out = {}
    for start, table in _lsda.parse_all(BNImage(bv)).items():
        for cs in table.call_sites:
            if cs.landing_pad is not None and cs.landing_pad not in out:
                kinds = ", ".join("catch(%s)" % (c.type if c.type is not None else "...") if c.kind == "catch"
                                  else c.kind for c in cs.clauses) or "cleanup"
                out[cs.landing_pad] = Pad(cs.landing_pad, start, kinds)
    return [out[a] for a in sorted(out)]


def missing(bv):
    """the pads no function starts at (in no function, or inside another one)"""
    return [p for p in pads(bv) if bv.get_function_at(p.addr) is None]


def _is_call(ref):
    from binaryninja import LowLevelILOperation
    try:
        il = ref.function.get_low_level_il_at(ref.address)
    except Exception:
        return False
    return il is not None and il.operation == LowLevelILOperation.LLIL_CALL


def terminate_helpers(bv):
    """[(helper, terminate)]: clang's ___clang_call_terminate, named or not -- at most 32 bytes, called from code
    (a terminate guard calls it; a small catch handler BN split off a pad starts the same way but is only jumped
    to, from its owner -- SynthV: begin_catch, then end_catch or a hashed import),
    the first call within 8 bytes of the start goes to ___cxa_begin_catch, the second to an imported function
    (std::terminate is libc++'s) named std::terminate or hashed. What follows does not count: while BN thinks
    terminate returns, it runs on into the next function and lists that as a callee too."""
    from binaryninja import SymbolType
    imported = (SymbolType.ImportedFunctionSymbol, SymbolType.ImportAddressSymbol, SymbolType.ExternalSymbol)
    out = []
    for f in bv.functions:
        if f.total_bytes > 32:
            continue
        sites = sorted(f.call_sites, key=lambda r: r.address)
        if len(sites) < 2 or sites[0].address - f.start > 8:
            continue
        first, second = ([bv.get_function_at(a) for a in bv.get_callees(r.address, r.function)]
                         for r in sites[:2])
        if len(first) != 1 or first[0] is None or first[0].name.lstrip("_") != "cxa_begin_catch":
            continue
        if len(second) != 1 or second[0] is None or second[0] == f or second[0].symbol.type not in imported:
            continue
        # std::terminate by name, or a name that says nothing (hashed); an ABI or C++ name that is not terminate
        # returns (SynthV: begin_catch then ___cxa_end_catch in a handler its owner calls)
        t = second[0].name.lstrip("_")
        if t != "ZSt9terminatev" and (t.startswith("cxa_") or t.startswith("Z")):
            continue
        if not any(_is_call(r) for r in bv.get_code_refs(f.start) if r.function is not None and r.function != f):
            continue
        out.append((f, second[0]))
    return out


def noreturn_todo(bv, protected=None):
    """the functions of terminate_helpers BN still lets return, unless protected(f) (default: a user type)"""
    protected = protected or (lambda f: f.has_user_type)
    todo = []
    for pair in terminate_helpers(bv):
        for f in pair:
            if f.can_return.value and not protected(f) and f not in todo:
                todo.append(f)
    return todo


def mark_noreturn(bv, todo):
    """a __noreturn user type (the current type otherwise) on every function in todo, then analysis
    (Function.can_return's setter does nothing in BN 6.1; the user type does and survives re-analysis)"""
    for f in todo:
        b = f.type.mutable_copy()
        b.can_return = False
        f.set_user_type(b.immutable_copy())
    if todo:
        bv.update_analysis_and_wait()
    return todo


def create(bv, todo=None):
    """a user function at every pad in todo (default: missing(bv)), then analysis; returns the pads created"""
    todo = missing(bv) if todo is None else todo
    for p in todo:
        bv.create_user_function(p.addr)
    if todo:
        bv.update_analysis_and_wait()
    return todo


def recover(bv, protected=None):
    """mark_noreturn, then create: ([functions marked], [pads created])"""
    return mark_noreturn(bv, noreturn_todo(bv, protected)), create(bv)


def register_command(prefix):
    """the plugin command '<prefix>\\Create landing-pad functions' (in a background task)"""
    from binaryninja import BackgroundTaskThread, PluginCommand, log_info

    class _Task(BackgroundTaskThread):
        def __init__(self, bv):
            BackgroundTaskThread.__init__(self, "Creating landing-pad functions", False)
            self.bv = bv

        def run(self):
            marked, made = recover(self.bv)
            if marked:
                log_info("%s: marked __noreturn: %s" % (prefix, ", ".join(f.name for f in marked)))
            log_info("%s: created %d landing-pad functions%s" % (prefix, len(made), "".join(
                "\n  %#x (%s) for %s" % (p.addr, p.kinds, self.bv.get_symbol_at(p.owner).full_name
                                         if self.bv.get_symbol_at(p.owner) else "%#x" % p.owner) for p in made)))

    PluginCommand.register(prefix + "\\Create landing-pad functions",
                           "Create a function at every C++ landing pad (LSDA) that has none, so no handler code "
                           "is lost (bncpp-4)", lambda bv: _Task(bv).start())
