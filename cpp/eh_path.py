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
  rethrown    caught by a handler that rethrows (`throw;`): the same exception goes on from the rethrow call
              (bncpp-70); a handler that throws another exception starts a second path with that type
Functions on the path without direct callers go on to their virtual callers where a vcallers hook gives them
(bncpp-66, cpp/eh_virtual.py: the calls through the X::VTable members of the slots holding the function; steps
marked 'virtual'). Functions with neither are the frontier (entry points, or reached only through function
pointers, or through receivers BN has no class type for).

Prototype: the offline catch_bfs.py of 2026-10-12 (bncpp session, copied into synVbasic's scripts): the same
walk over objdump and the file's own tables; here BN's call graph (shared/callgraph.py) and cpp/bnimage.py.
"""
import bisect
from collections import deque

from . import lsda as _lsda, std_exceptions, unwind_info

PREFIX = "[eh] "  # our comments; any other comment at the address is the user's and stays


class Step:
    __slots__ = ("kind", "site", "owner", "via", "pad", "clause", "virtual")

    def __init__(self, kind, site, owner, via, pad=None, clause=None, virtual=False):
        self.kind, self.site, self.owner, self.via = kind, site, owner, via  # via: the callee on the path
        self.pad, self.clause = pad, clause  # clause: [Clause] for caught / may catch
        self.virtual = virtual  # a virtual call of via (bncpp-66)


class Trace:
    def __init__(self, bv, img, edges, thrown=(), bases=None, guards=(), vcallers=None):
        """thrown: the typeinfos thrown (addresses or names; empty: unknown); bases(ti) -> the typeinfos of its
        bases (addresses / names), None when not known; guards: addresses of terminate helpers; vcallers(fn) ->
        [(call address, caller, tail?)]: its virtual call sites (cpp/eh_virtual.py), None: direct calls only"""
        from ..shared import callgraph
        self.bv, self.img = bv, img
        self.callers = callgraph.index(edges)[0]
        self.starts = [f.addr for f in unwind_info.functions(img)]
        self.tables = _lsda.parse_all(img)
        self.bases = bases
        self.guards = set(guards)
        self.vcallers = vcallers
        self.thrown = [self.keys(t) for t in thrown]
        self.steps, self.frontier, self.seen = [], [], set()
        self.paths, self.depth = [], 0  # paths: [(catching step, throw site, typeinfo, Trace)] (bncpp-70)

    def child(self, thrown):
        """a trace of another exception over the same binary (the tables and the call graph shared)"""
        t = Trace.__new__(Trace)
        t.bv, t.img, t.callers, t.starts, t.tables = self.bv, self.img, self.callers, self.starts, self.tables
        t.bases, t.guards, t.vcallers = self.bases, self.guards, self.vcallers
        t.thrown = [t.keys(x) for x in thrown]
        t.steps, t.frontier, t.seen, t.paths, t.depth = [], [], set(), [], self.depth + 1
        return t

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

    def handler_throws(self, owner, cs, clause):
        """(rethrow sites, [(throw site, typeinfo)]) of the handler of clause: the landing pad's code with the
        selector fixed to the clause (eh_render.specialize, as the try/catch rendering splits it)"""
        from .eh_render import callee, specialize
        from ..shared.hlil import walk
        pf = self.bv.get_function_at(cs.landing_pad)
        if pf is None or clause.type_index is None:
            return [], []
        try:
            h = specialize(pf, clause.type_index, sum(c.kind == c.CATCH for c in cs.clauses),
                           self.bv.get_function_at(owner))
        except Exception:
            return [], []
        rethrows, throws = [], []
        for st in (h.stmts[h.before:] if h is not None else ()):  # (before the dispatch: the unwind cleanups)
            for i in walk(st):
                name = callee(i)
                if name == "cxa_rethrow" and i.address not in rethrows:
                    rethrows.append(i.address)
                elif name == "cxa_throw" and len(i.params) >= 2 and hasattr(i.params[1], "constant") and \
                        (i.address, i.params[1].constant) not in throws:
                    throws.append((i.address, i.params[1].constant))
        return rethrows, throws

    def throw_site(self, site, queue, via=None):
        """the exception leaves a throw (or rethrow) call at site: its owner's table decides first"""
        if site in self.done_sites:
            return
        self.done_sites.add(site)
        own = self.owner(site)
        kind, cs, clause = self.decide(own, site)
        st = Step(kind, site, own, via if via is not None else own, cs.landing_pad if cs else None, clause)
        self.steps.append(st)
        self.after_step(st, cs, queue)

    def after_step(self, st, cs, queue):
        """go on from a step: to the owner's callers, or on from the handler that caught it -- a rethrow sends the
        same exception on from the rethrow site ('rethrown'), a new throw starts a second path (bncpp-70)"""
        if st.kind == "caught":
            rethrows, throws = self.handler_throws(st.owner, cs, st.clause[-1])
            if rethrows:
                st.kind = "rethrown"
                for site in rethrows:
                    self.throw_site(site, queue, st.owner)
            self.pending += [(st, site, ti) for site, ti in throws]
        elif st.kind in ("tail", "unwind", "cleanup", "may catch") and st.owner not in self.seen:
            self.seen.add(st.owner)
            queue.append(st.owner)

    def run(self, starts=(), sites=()):
        """starts: functions the exception leaves (their callers decide); sites: throw sites (the call to
        ___cxa_throw decides in its own owner's table first -- a throw in a catch body or inside a try)"""
        queue, self.seen, self.done_sites, self.pending = deque(), set(), set(), []
        for site in sites:
            self.throw_site(site, queue)
        for fn in starts:
            if fn not in self.seen:
                self.seen.add(fn)
                queue.append(fn)
        while queue:
            fn = queue.popleft()
            sites = {site: None for site, _caller in self.callers.get(fn, [])}  # a site BN lists twice: once
            for site, _caller, tail in (self.vcallers(fn) if self.vcallers is not None else ()):
                sites.setdefault(site, tail)  # virtual: tail from the IL (an indirect call has no branch target)
            if not sites:
                self.frontier.append(fn)
                continue
            for site, vtail in sorted(sites.items()):
                own = self.owner(site)
                if (self.is_tail(site) if vtail is None else vtail):
                    kind, cs, clause = "tail", None, None
                else:
                    kind, cs, clause = self.decide(own, site)
                st = Step(kind, site, own, fn, cs.landing_pad if cs else None, clause, vtail is not None)
                self.steps.append(st)
                self.after_step(st, cs, queue)
        done = set()
        for st, site, ti in self.pending:  # handlers that throw another exception: one more trace each
            if (site, ti) in done or self.depth >= 3:
                continue
            done.add((site, ti))
            self.paths.append((st, site, ti, self.child([ti]).run(sites=[site])))
        return self

    # --- output ----------------------------------------------------------------------------------------------

    def name(self, addr):
        f = self.bv.get_function_at(addr)
        return f.symbol.full_name if f is not None else "%#x" % addr

    def comment(self, st):
        from .eh_comments import clause_text
        via = self.name(st.via) + (" (virtual call)" if st.virtual else "")
        if st.kind in ("caught", "may catch", "rethrown"):
            # caught: the clause that takes it last, any earlier ones could have (bases unknown)
            return PREFIX + "%s %s from %s: landing pad %#x" % (
                {"caught": "caught by", "may catch": "may be caught by",
                 "rethrown": "caught and rethrown (throw;) by"}[st.kind],
                " or ".join(clause_text(c) for c in st.clause), via, st.pad)
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
        nv = sum(1 for st in self.steps if st.virtual)
        members = getattr(self.vcallers, "members", None)
        nvt = sum(1 for fn in self.frontier if fn in members) if members is not None else 0
        out = ["functions on the path: %d; %s%s; frontier (no callers): %d%s" % (
            len(self.seen), ", ".join("%s %d" % kv for kv in sorted(count.items())) or "no callers",
            "; virtual call sites %d" % nv if nv else "", len(self.frontier),
            " (%d in a vtable: no virtual call through a typed receiver)" % nvt if nvt else "")]
        for st in self.steps:
            if st.kind in ("caught", "may catch", "terminates", "rethrown"):
                out.append("  %-10s %#x in %s  %s" % (st.kind + ("*" if st.virtual else ""), st.site,
                                                      self.name(st.owner), self.comment(st)))
        if self.frontier:
            out.append("  frontier: " + " ".join(self.name(a) for a in self.frontier))
        for st, site, ti, sub in self.paths:
            s = self.bv.get_symbol_at(ti)
            out.append("  then: the handler in %s (landing pad %#x) throws %s at %#x:" % (
                self.name(st.owner), st.pad, s.full_name if s is not None else "%#x" % ti, site))
            out += ["    " + line for line in sub.report()]
        return out

    def all_steps(self):
        """the steps of this path and of the paths its handlers start"""
        out = list(self.steps)
        for _st, _site, _ti, sub in self.paths:
            out += sub.all_steps()
        return out

    def annotate(self, apply=True):
        """our comment at every call site on the path (in the function BN has there), the first path's where
        two meet; never over another comment. Returns (set, skipped)"""
        done, skipped, seen = 0, 0, set()
        for st in self.all_steps():
            if st.site in seen:
                continue
            seen.add(st.site)
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
            from . import rtti, rtti_names
            from .eh_virtual import VirtualCallers
            types = rtti.scan(img)
            labels = rtti_names.labels(types, img.demangle, rtti_names.label_overrides(types, img.symbol_at))
            t = Trace(self.bv, img, edges, thrown_types(self.func), rtti_bases(img), guards,
                      VirtualCallers(self.bv, types, labels))
            t.run(sites=sites) if sites else t.run([self.func.start])  # no throw here: it leaves this function
            t.annotate()
            log_info("%s: exception path from %s (thrown: %s)\n%s" % (
                prefix, self.func.symbol.full_name, ", ".join(map(str, thrown_types(self.func))) or "unknown",
                "\n".join(t.report())))

    PluginCommand.register_for_function(
        prefix + "\\Exception path from here",
        "Follow what this function throws up the direct callers: who catches it, where it terminates; comments "
        "at every call site on the path (bncpp-24)", lambda bv, f: _Task(bv, f).start())
