---
name: cpp
description: Project skill for binary-cpp, a Binary Ninja plugin for readable C++ ("Pseudo Cpp" language view; try/catch rebuilt from Itanium / MSVC exception tables, readability passes on HLIL), seeded from the binary-jvm project. Use when working in /Users/patrick/dev/binary-cpp -- designing or writing the plugin, building or dumping the C++ test suite, inspecting HLIL in the running Binary Ninja, or re-using code and test tooling from binary-jvm.
---

# binary-cpp project workflow

Documentation: miniwiki project `bncpp` (skill `miniwiki-api`); backlog: minitick project `bncpp` (skill
`minitick-api`); environment, commands and rules: `CLAUDE.md`. Generic Binary Ninja mechanics (`bnrun`
script bridge, usage lock, Personal-license workarounds): skill `binaryninja-bridge`.

## Workflow per ticket
1. `export MINITICK_URL=http://192.168.1.147:8000`; `minitick get -p bncpp N --expand comment`; set it
   IN PROGRESS (`minitick update -p bncpp N -f status="IN PROGRESS"`). Wiki: `miniwiki --api-url
   http://192.168.1.147:8001 …`.
2. Read the binary-jvm equivalent first (wiki `reuse-from-binary-jvm.md`).
3. Change the code; add or extend a suite test (`tests/suite/src/TestX.cpp` + `TESTS` in `suite.py`).
4. `suite.py build` (if sources changed) → `bn_dev_load.py` → `bn_dump.py` → `suite.py compare --diff`;
   review every difference, then `suite.py accept`.
5. One commit; ticket comment with the numbers; RESOLVED. Findings into the wiki pages.

## Gotchas (details: wiki `plugin-architecture.md`, `eh-in-hlil.md`)
- BN calls `perform_get_expr_text` once with the root block. Copying Pseudo C needs `settings=None`, empty
  lines → `scope_separator()`, and a final `new_line()`.
- Exceptions inside `perform_*` callbacks are swallowed by BN (logged only) → an empty `{ }` body.
- BN cannot unregister a language: every dev load registers "Pseudo Cpp devN"; `bn_dump.py` uses the latest.
- Landing pads are separate functions in BN, and some handler code is in no function at all (bncpp-4).
- Shared code (`shared/`): no imports from `cpp/`, hooks for language specifics, provenance header, row in the
  wiki `code-structure.md` table; mirror the split in binary-jvm (jvm-68, bncpp-14).

## Gotchas: classes and databases (details: wiki `classes.md`)
- BN 6.1 resolves Mach-O binds through the nlist names: where an obfuscator hashed them (SynthV), the typeinfo
  vptr binds and some imports are gone and BN's RTTI finds 0 vtables (bncpp-25). `cpp/rtti.py` falls back to the
  layout; check any change with `tests/ref_class_scan.py --compare` (0 missing, structure ≤ 2 on SynthV).
- `f.has_user_type` can be True for every function of a `.bndb` (synVbasic's), though nobody set types: protect
  only types that differ from BN's fresh inference (`bn_class_types.py` `BASELINE` / `DUMP_TYPES`).
- A named type reference (a data var's type) has no `.members`: resolve it (`bv.get_type_by_name`).
- In shell heredocs that carry Markdown, quote the delimiter (`<<'EOF'`) -- or the backticks run as commands.
