# shared with binary-jvm/pseudo_java.py (display_names / name_hint / name_from_method / unique_name, jvm-55;
# synced at a01bc06 as a translation -- back-port the cut, bncpp-14/jvm-68); keep language-neutral
"""Display names for a function's auto-named variables, from the value they hold (bncpp-107).

A register or stack slot BN names after its storage (rax_12, var_38) reads as noise where it holds a value that
says what it is: a field load (`r12 = this->buckets` -> buckets), a call result (`rax = next_value()` -> value), a
counter (`i = 0` ... `i = i + 1` -> i). NamesMixin picks such a name, unique in the function and never one of its
other names; render time only -- nothing is written to the database, a user's name is never touched.

What the language class must provide (hooks):
  hlil                              the HighLevelILFunction
  auto_named(var)      -> bool      var carries BN's storage name, not a user's or a parameter's
  name_hint(expr)      -> str/None  a name for a variable assigned expr (a definition's source)
  taken_names()        -> set       (optional) names the function prints otherwise: callees, globals, keywords
NamesMixin keeps:
  self._names   {var: display name}, computed once (display_names())
"""
import re

from binaryninja import HighLevelILOperation

from .hlil import walk

Op = HighLevelILOperation

_DEFS = (Op.HLIL_VAR_INIT, Op.HLIL_ASSIGN)
COUNTER = "i"  # var_hint's name for a counter: set to a constant, stepped by constants (i, j, k, i2, ...)
_STEPS = (Op.HLIL_ADD, Op.HLIL_SUB)
_HASH = re.compile(r"^(?=.*\d)[0-9a-f]{8,}$")  # a hashed symbol (ac15664b2f005e0)
# a verb that makes the rest of a function's name the thing it returns: get_size -> size, nextElement -> element
_PREFIX = re.compile(r"^(?:get|is|has|to|create|new|read|next|find|load|fetch|build|make|parse|as|alloc|compute)"
                     r"(?:_+(?=[a-z])|(?=[A-Z0-9]))(.+)$")


def name_from_call(name):
    """a variable's name from the function whose result it holds: get_size / getSize -> size, next_value -> value,
    strlen -> strlen_result; None for nothing usable (operators, destructors, templates, auto names, the ABI's __x)"""
    if not name or name.startswith(("operator", "~", "sub_", "j_", "__")) or not re.match(r"^_?[A-Za-z]\w*$", name):
        return None  # (__x: the ABI's and the runtime's: ___cxa_begin_catch, ___dynamic_cast)
    name = name.lstrip("_")
    if _HASH.match(name):
        return None  # an obfuscator's name says nothing
    m = _PREFIX.match(name)
    if m is None:
        return name + "_result"
    rest = m.group(1)
    if rest.isupper():
        rest = rest.lower()
    return rest[0].lower() + rest[1:]


def unique_name(base, taken):
    """base, base2, base3, ... not in taken (which is updated)"""
    name, n = base, 2
    while name in taken:
        name = "%s%d" % (base, n)
        n += 1
    taken.add(name)
    return name


class NamesMixin:
    _names = None

    def taken_names(self):
        return set()

    def display_names(self):
        """{auto-named variable: name}, for the variables whose every definition suggests the same name (a counter:
        a constant, then stepped); others keep BN's name"""
        if self._names is not None:
            return self._names
        names = {}
        try:
            hlil = self.hlil
            seen, auto, taken = set(), [], set(self.taken_names())
            for i in walk(hlil.root):
                o = i.operation
                v = i.dest if o == Op.HLIL_VAR_INIT else i.var if o in (Op.HLIL_VAR, Op.HLIL_VAR_DECLARE) else None
                if v is None or v in seen:
                    continue
                seen.add(v)
                if self.auto_named(v):
                    auto.append(v)
                else:
                    taken.add(v.name)
            for v in hlil.source_function.parameter_vars:
                taken.add(v.name)
            taken.update(v.name for v in auto)
            for v in auto:
                hint = self.var_hint(v)
                if hint == COUNTER:  # i, j, k, then i2, ...
                    names[v] = next((n for n in "ijk" if n not in taken), None) or unique_name("i", taken)
                    taken.add(names[v])
                elif hint:
                    names[v] = unique_name(hint, taken)
        except Exception:
            names = {}
        self._names = names
        return names

    def var_hint(self, var):
        """the one name all of var's definitions suggest, else None"""
        defs = [d for d in self.hlil.get_var_definitions(var) if d.operation in _DEFS]
        if not defs:
            return None
        if len(defs) >= 2 and any(d.src.operation == Op.HLIL_CONST for d in defs) and \
                all(d.src.operation == Op.HLIL_CONST or _step(d.src, var) for d in defs) and \
                any(_step(d.src, var) for d in defs):
            return COUNTER
        hints = {self.name_hint(d.src) for d in defs}
        return hints.pop() if len(hints) == 1 else None


def _step(e, var):
    """e is var + c / var - c with a constant c (a counter's step, not a sum's)"""
    return e.operation in _STEPS and e.left.operation == Op.HLIL_VAR and e.left.var == var and \
        e.right.operation == Op.HLIL_CONST
