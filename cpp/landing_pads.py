"""Landing pads Binary Ninja did not make functions (bncpp-4).

BN never follows the unwind edge from a call site to its landing pad: a pad is either split off as a function of
its own (sub_...) or, often for catch (...) and cleanup pads, in no function at all -- its handler code is then in
no view (wiki eh-in-hlil.md). The LSDA names every pad, so a function is created at each one that has none; the
try/catch rendering (bncpp-6) finds the handler as the function at the pad's address.

Creating functions changes the view: in the plugin it is a command, never automatic (another session's database
changes only through its own lane: tests/bn_landing_pads.py dry run + review first, then APPLY).
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


def create(bv, todo=None):
    """a user function at every pad in todo (default: missing(bv)), then analysis; returns the pads created"""
    todo = missing(bv) if todo is None else todo
    for p in todo:
        bv.create_user_function(p.addr)
    if todo:
        bv.update_analysis_and_wait()
    return todo


def register_command(prefix):
    """the plugin command '<prefix>\\Create landing-pad functions' (in a background task)"""
    from binaryninja import BackgroundTaskThread, PluginCommand, log_info

    class _Task(BackgroundTaskThread):
        def __init__(self, bv):
            BackgroundTaskThread.__init__(self, "Creating landing-pad functions", False)
            self.bv = bv

        def run(self):
            made = create(self.bv)
            log_info("%s: created %d landing-pad functions%s" % (prefix, len(made), "".join(
                "\n  %#x (%s) for %s" % (p.addr, p.kinds, self.bv.get_symbol_at(p.owner).full_name
                                         if self.bv.get_symbol_at(p.owner) else "%#x" % p.owner) for p in made)))

    PluginCommand.register(prefix + "\\Create landing-pad functions",
                           "Create a function at every C++ landing pad (LSDA) that has none, so no handler code "
                           "is lost (bncpp-4)", lambda bv: _Task(bv).start())
