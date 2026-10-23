"""The standard library's exception hierarchy (bncpp-69), for base-class matching of imported typeinfos.

The std exception typeinfos are imports (from libc++ / libstdc++): their bases are not in the binary, so a
`catch (std::exception)` of a thrown std::runtime_error could only be a 'may catch' (cpp/eh_path.py). This is the
standard's own hierarchy ([std.exceptions], [syserr], [except.nested] ...), keyed by the class name without the
library's inline namespace (libc++ puts some of them in std::__1: future_error, system_error, ios_base::failure,
bad_function_call, bad_weak_ptr, filesystem_error; libstdc++ in std::__cxx11 for the C++11-ABI ios_base::failure).
"""
import re

BASES = {
    "std::exception": (),
    "std::bad_exception": ("std::exception",),
    "std::logic_error": ("std::exception",),
    "std::invalid_argument": ("std::logic_error",),
    "std::domain_error": ("std::logic_error",),
    "std::length_error": ("std::logic_error",),
    "std::out_of_range": ("std::logic_error",),
    "std::future_error": ("std::logic_error",),
    "std::runtime_error": ("std::exception",),
    "std::range_error": ("std::runtime_error",),
    "std::overflow_error": ("std::runtime_error",),
    "std::underflow_error": ("std::runtime_error",),
    "std::regex_error": ("std::runtime_error",),
    "std::system_error": ("std::runtime_error",),
    "std::ios_base::failure": ("std::system_error",),
    "std::filesystem::filesystem_error": ("std::system_error",),
    "std::format_error": ("std::runtime_error",),
    "std::bad_alloc": ("std::exception",),
    "std::bad_array_new_length": ("std::bad_alloc",),
    "std::bad_cast": ("std::exception",),
    "std::bad_any_cast": ("std::bad_cast",),
    "std::bad_typeid": ("std::exception",),
    "std::bad_function_call": ("std::exception",),
    "std::bad_weak_ptr": ("std::exception",),
    "std::bad_variant_access": ("std::exception",),
    "std::bad_optional_access": ("std::exception",),
}

# the library's throw helpers (bncpp-92): libc++'s inline std::__1::__throw_X (also as members of vector / basic_string
# ...), libstdc++'s exported std::__throw_X -- a call to one is a throw of the class
THROWERS = {
    "__throw_out_of_range": "std::out_of_range",
    "__throw_out_of_range_fmt": "std::out_of_range",
    "__throw_length_error": "std::length_error",
    "__throw_logic_error": "std::logic_error",
    "__throw_invalid_argument": "std::invalid_argument",
    "__throw_domain_error": "std::domain_error",
    "__throw_runtime_error": "std::runtime_error",
    "__throw_range_error": "std::range_error",
    "__throw_overflow_error": "std::overflow_error",
    "__throw_underflow_error": "std::underflow_error",
    "__throw_regex_error": "std::regex_error",
    "__throw_system_error": "std::system_error",
    "__throw_ios_failure": "std::ios_base::failure",
    "__throw_failure": "std::ios_base::failure",
    "__throw_format_error": "std::format_error",
    "__throw_future_error": "std::future_error",
    "__throw_bad_alloc": "std::bad_alloc",
    "__throw_bad_array_new_length": "std::bad_array_new_length",
    "__throw_bad_cast": "std::bad_cast",
    "__throw_bad_any_cast": "std::bad_any_cast",
    "__throw_bad_typeid": "std::bad_typeid",
    "__throw_bad_exception": "std::bad_exception",
    "__throw_bad_function_call": "std::bad_function_call",
    "__throw_bad_weak_ptr": "std::bad_weak_ptr",
    "__throw_bad_optional_access": "std::bad_optional_access",
    "__throw_bad_variant_access": "std::bad_variant_access",
}

_PREFIX = re.compile(r"^(?:typeinfo[ _]for[ _]|_*ZTI)")


def class_name(key):
    """the std class a typeinfo name stands for, without inline namespaces (`std::__1::system_error` ->
    `std::system_error`), or None: a mangled `__ZTISt13runtime_error` / `__ZTINSt3__112system_errorE`, BN's
    `typeinfo_for_std::runtime_error`, a demangled `typeinfo for std::runtime_error`"""
    if not isinstance(key, str):
        return None
    m = _PREFIX.match(key)
    if m is None:
        return None
    rest = key[m.end():]
    name = _demangle(rest) if key[m.start():m.end()].lstrip("_").startswith("ZTI") else rest
    if name is None:
        return None
    name = "::".join(p for p in name.split("::") if not p.startswith("__"))  # __1, __fs, __cxx11
    return name if name in BASES else None


def thrower_class(name):
    """the std class a library throw helper throws, by its demangled name (`std::__1::__throw_out_of_range[abi:x]
    (char const*)`, `std::__1::vector<int>::__throw_out_of_range()`, `std::__throw_bad_alloc()`), else None"""
    if not isinstance(name, str) or not name.startswith("std::"):
        return None
    base = re.sub(r"\[abi:[^\]]*\]", "", name.split("(")[0])
    return THROWERS.get(base.rsplit("::", 1)[-1])


def bases(name):
    """the direct bases of the std class name (class_name's form), None when it is not one"""
    return BASES.get(name)


def _demangle(s):
    """the Itanium <type> of a typeinfo for the shapes the std exceptions have: `St<n><id>` (std::id) and
    `N<prefix>(<n><id>)+E` with St as the first component; None for anything else"""
    if s.startswith("St"):
        parts, pos, nested = ["std"], 2, False
    elif s.startswith("NSt"):
        parts, pos, nested = ["std"], 3, True
    else:
        return None
    while pos < len(s) and s[pos].isdigit():
        m = re.match(r"\d+", s[pos:])
        n = int(m.group(0))
        pos += len(m.group(0))
        parts.append(s[pos:pos + n])
        pos += n
        if not nested:
            break
    if nested and s[pos:] != "E" or not nested and pos != len(s):
        return None
    return "::".join(parts)
