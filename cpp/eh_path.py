"""Who catches what a function throws (bncpp-24): the exception's path up the direct call graph.

From the throwing functions, every direct call to a function on the path is looked up in the caller's LSDA (the
owner: the compact-unwind function containing the call, so a pad or a piece BN split off counts as its owner) and
the personality's decision is repeated:
  caught      a catch clause takes the type (catch (...), the thrown type, a base of it)
  terminates  the clause is a terminate guard (catch (...) whose pad calls clang's terminate helper: a noexcept
              boundary, not a handler), or the call has no call-site entry although the owner has an LSDA
  may catch   catch (T) where the thrown type is unknown or its bases are not in the binary (an imported typeinfo
              other than the std exceptions, whose hierarchy is built in: cpp/std_exceptions.py, bncpp-69)
              -- reported, and the path goes on
  cleanup     only cleanups (destructors) -- the exception goes on to the owner's callers
  unwind      no landing pad / no LSDA -- goes on
  tail        a tail jump: the caller's frame is gone, the exception goes on to the owner's callers
Functions on the path without direct callers are the frontier (entry points, or reached only indirectly: virtual
calls, function pointers -- not followed yet).

Prototype: the offline catch_bfs.py of 2026-10-12 (bncpp session, copied into synVbasic's scripts): the same
walk over objdump and the file's own tables; here BN's call graph (shared/callgraph.py) and cpp/bnimage.py.
"""
import bisect
from collections import deque

from . import lsda as _lsda, std_exceptions, unwind_info

PREFIX = "[eh] "  # our comments; any other comment at the address is the user's and stays


class Step:
    __slots__ = ("kind", "site", "owner", "via", "pad", "clause")

    def __init__(self, kind, site, owner, via, pad=None, clause=None):
        self.kind, self.site, self.owner, self.via = kind, site, owner, via  # via: the callee on the path
        self.pad, self.clause = pad, clause  # clause: [Clause] for caught / may catch


class Trace:
    def __init__(self, bv, img, edges, thrown=(), bases=None, guards=()):
        """thrown: the typeinfos thrown (addresses or names; empty: unknown); bases(ti) -> the typeinfos of its
        bases (addresses / names), None when not known; guards: addresses of terminate helpers"""
        from ..shared import callgraph
        self.bv, self.img = bv, img
        self.callers = callgraph.index(edges)[0]
        self.starts = [f.addr for f in unwind_info.functions(img)]
        self.tables = _lsda.parse_all(img)
        self.bases = bases
        self.guards = set(guards)
        self.thrown = [self.keys(t) for t in thrown]
        self.steps, self.frontier, self.seen = [], [], set()

    # --- types -----------------------------------------------------------------------------------------------

    def keys(self, t):
        """the names and addresses a typeinfo goes by (an import slot's symbol, a local typeinfo's address; a std
        exception also by its class name, cpp/std_exceptions.py)"""
        out = {t}
        if isinstance(t, int):
            s = self.bv.get_symbol_at(t)
            if s is not None:
                out |= {s.raw_name, s.full_name}
            target = self.img.pointer_target(t)
            if isinstance(target, str):
                out.add(target)
        elif std_exceptions.bases(t) is None:
            out |= set(self.img.symbol_keys(t))
        out |= {n for n in map(std_exceptions.class_name, list(out)) if n is not None}
        return out

    def ancestors(self, t, depth=0):
        """keys of every base of t (transitively); None if t's bases are not known. Bases from the class scan
        (self.bases), or for a std exception (an import) from the standard's hierarchy"""
        if depth > 16:
            return None
        bs = self.bases(t) if self.bases is not None else None
        if bs is None:
            std = [std_exceptions.bases(n) for n in self.keys(t) if std_exceptions.bases(n) is not None]
            if not std:
                return None
            bs = list(std[0])
        out = set()
        for b in bs:
            out |= self.keys(b)
            more = self.ancestors(b, depth + 1)
            if more:
                out |= more
        return out

    def matches(self, clause_type):
        """True: some thrown type is caught by catch (clause_type); False: none is; None: cannot tell"""
        if not self.thrown:
            return None
        ck = self.keys(clause_type)
        unknown = False
        for tk in self.thrown:
            if tk & ck:
                return True
            if _scalar(ck) or _scalar(tk):
                continue  # a fundamental or pointer type has no bases and is no base: exact match only
            anc = None
            for k in sorted(tk, key=lambda k: not isinstance(k, int)):  # an address first: the class scan's
                anc = self.ancestors(k)
                if anc is not None:
                    break
            if anc is None:
                unknown = True
            elif anc & ck:
                return True
        return None if unknown else False

    # --- the walk --------------------------------------------------------------------------------------------

    def owner(self, addr):
        i = bisect.bisect_right(self.starts, addr) - 1
        if i >= 0:
            return self.starts[i]
        funcs = self.bv.get_functions_containing(addr)
        return funcs[0].start if funcs else addr

    def is_tail(self, site):
        from binaryninja import BranchType
        bv = self.bv
        info = bv.arch.get_instruction_info(bv.read(site, bv.arch.max_instr_length), site)
        return info is not None and not any(b.type == BranchType.CallDestination for b in info.branches)

    def is_guard(self, pad):
        from .eh_render import is_terminate_guard
        return is_terminate_guard(self.bv, pad, self.guards)

    def decide(self, owner, site):
        """(kind, call site entry | None, clause | None) for an exception leaving the call at site"""
        table = self.tables.get(owner)
        if table is None:
            return "unwind", None, None
        cs = next((c for c in table.call_sites if c.start <= site < c.end), None)
        if cs is None:
            return "terminates", None, None  # the personality calls std::terminate
        if cs.landing_pad is None:
            return "unwind", cs, None
        maybe = []
        for c in cs.clauses:
            if c.kind != c.CATCH:
                continue
            m = True if c.type is None else self.matches(c.type)
            if m:
                return ("terminates" if self.is_guard(cs.landing_pad) else "caught"), cs, maybe + [c]
            if m is None:
                maybe.append(c)
        if maybe:
            return "may catch", cs, maybe
        return "cleanup", cs, None

    def run(self, starts=(), sites=()):
        """starts: functions the exception leaves (their callers decide); sites: throw sites (the call to
        ___cxa_throw decides in its own owner's table first -- a throw in a catch body or inside a try)"""
        queue, self.seen = deque(), set()
        for site in sites:
            own = self.owner(site)
            kind, cs, clause = self.decide(own, site)
            self.steps.append(Step(kind, site, own, own, cs.landing_pad if cs else None, clause))
            if kind in ("unwind", "cleanup", "may catch") and own not in self.seen:
                self.seen.add(own)
                queue.append(own)
        for fn in starts:
            if fn not in self.seen:
                self.seen.add(fn)
                queue.append(fn)
        while queue:
            fn = queue.popleft()
            sites = self.callers.get(fn, [])
            if not sites:
                self.frontier.append(fn)
                continue
            for site in sorted({site for site, _caller in sites}):  # a site BN lists under two callers once
                own = self.owner(site)
                if self.is_tail(site):
                    kind, cs, clause = "tail", None, None
                else:
                    kind, cs, clause = self.decide(own, site)
                self.steps.append(Step(kind, site, own, fn, cs.landing_pad if cs else None, clause))
                if kind in ("tail", "unwind", "cleanup", "may catch") and own not in self.seen:
                    self.seen.add(own)
                    queue.append(own)
        return self

    # --- output ----------------------------------------------------------------------------------------------

    def name(self, addr):
        f = self.bv.get_function_at(addr)
        return f.symbol.full_name if f is not None else "%#x" % addr

    def comment(self, st):
        from .eh_comments import clause_text
        via = self.name(st.via)
        if st.kind in ("caught", "may catch"):
            # caught: the clause that takes it last, any earlier ones could have (bases unknown)
            return PREFIX + "%s %s from %s: landing pad %#x" % (
                "caught by" if st.kind == "caught" else "may be caught by", " or ".join(
                    clause_text(c) for c in st.clause), via, st.pad)
        if st.kind == "terminates":
            if st.pad is None:
                return PREFIX + "terminates: no call-site entry for this call (exception from %s)" % via
            return PREFIX + "terminates: catch (...) terminate guard at %#x (exception from %s)" % (st.pad, via)
        if st.kind == "cleanup":
            return PREFIX + "unwinds through: cleanup at %#x (exception from %s)" % (st.pad, via)
        if st.kind == "tail":
            return PREFIX + "unwinds through: tail call (exception from %s)" % via
        return PREFIX + "unwinds through: no landing pad (exception from %s)" % via

    def report(self):
        count = {}
        for st in self.steps:
            count[st.kind] = count.get(st.kind, 0) + 1
        out = ["functions on the path: %d; %s; frontier (no direct callers): %d" % (
            len(self.seen), ", ".join("%s %d" % kv for kv in sorted(count.items())) or "no callers",
            len(self.frontier))]
        for st in self.steps:
            if st.kind in ("caught", "may catch", "terminates"):
                out.append("  %-10s %#x in %s  %s" % (st.kind, st.site, self.name(st.owner), self.comment(st)))
        if self.frontier:
            out.append("  frontier: " + " ".join(self.name(a) for a in self.frontier))
        return out

    def annotate(self, apply=True):
        """our comment at every call site on the path (in the function BN has there); never over another comment.
        Returns (set, skipped)"""
        done, skipped = 0, 0
        for st in self.steps:
            funcs = [f for f in self.bv.get_functions_containing(st.site) if f.start <= st.site]
            if not funcs:
                continue
            f = max(funcs, key=lambda f: f.start)
            old = f.get_comment_at(st.site)
            if old and not old.startswith(PREFIX):
                skipped += 1
                continue
            if apply:
                f.set_comment_at(st.site, self.comment(st))
            done += 1
        return done, skipped


def _scalar(keys):
    """a typeinfo of a fundamental or pointer type, by its names (typeinfo_for_int32_t, __ZTIi, __ZTIPKc)"""
    from .eh_comments import type_name
    from .eh_render import _SCALAR
    for k in keys:
        if isinstance(k, str):
            if _SCALAR.match(type_name(k)):
                return True
            if k.startswith("__ZTI") and (len(k) == 6 and k[5] in "abcdefghijlmnostvwxyz" or k[5] in "PK"):
                return True  # Itanium builtin type codes (__ZTIi = int) and pointers (__ZTIPKc)
    return False


def thrown_types(func):
    """the typeinfos func passes to ___cxa_throw (addresses), from its HLIL"""
    return list(dict.fromkeys(t for _site, t in throw_sites(func)))


def throw_sites(func):
    """[(call address, typeinfo address)] of func's calls to ___cxa_throw, from its HLIL"""
    from binaryninja import HighLevelILOperation as Op
    from ..shared.hlil import walk
    out = []
    hlil = func.hlil
    if hlil is None or hlil.root is None:
        return out
    for i in walk(hlil.root):
        if i.operation in (Op.HLIL_CALL, Op.HLIL_TAILCALL) and str(i.dest).lstrip("_") == "cxa_throw" and \
                len(i.params) >= 2 and hasattr(i.params[1], "constant") and (i.address, i.params[1].constant) not in out:
            out.append((i.address, i.params[1].constant))
    return out


def rtti_bases(img):
    """bases(ti) from the class scan (cpp/rtti.py): local typeinfos only; None for others (imports)"""
    from . import rtti
    types = rtti.scan(img)  # {typeinfo address: TypeInfo}
    return lambda t: [b for b, _ in types[t].bases] if isinstance(t, int) and t in types else None


def register_command(prefix):
    """'<prefix>\\Exception path from here' on a function: trace what it throws, comment the path"""
    from binaryninja import BackgroundTaskThread, PluginCommand, log_info

    class _Task(BackgroundTaskThread):
        def __init__(self, bv, func):
            BackgroundTaskThread.__init__(self, "Exception path from %s" % func.name, True)
            self.bv, self.func = bv, func

        def run(self):
            from ..shared import bncache, callgraph
            from . import landing_pads
            from .bnimage import BNImage
            img = BNImage(self.bv)
            edges = callgraph.edges(self.bv, bncache.Cache(self.bv))
            guards = [h.start for h, _t in landing_pads.terminate_helpers(self.bv)]
            sites = [a for a, _t in throw_sites(self.func)]
            t = Trace(self.bv, img, edges, thrown_types(self.func), rtti_bases(img), guards)
            t.run(sites=sites) if sites else t.run([self.func.start])  # no throw here: it leaves this function
            t.annotate()
            log_info("%s: exception path from %s (thrown: %s)\n%s" % (
                prefix, self.func.symbol.full_name, ", ".join(map(str, thrown_types(self.func))) or "unknown",
                "\n".join(t.report())))

    PluginCommand.register_for_function(
        prefix + "\\Exception path from here",
        "Follow what this function throws up the direct callers: who catches it, where it terminates; comments "
        "at every call site on the path (bncpp-24)", lambda bv, f: _Task(bv, f).start())
