---
name: bncpp
description: Project skill for binary-cpp, a Binary Ninja plugin for readable C++ ("Pseudo Cpp" language view; try/catch rebuilt from Itanium / MSVC exception tables, readability passes on HLIL), seeded from the binary-jvm project. Use when working in /Users/patrick/dev/binary-cpp -- designing or writing the plugin, building or dumping the C++ test suite, inspecting HLIL in the running Binary Ninja, or re-using code and test tooling from binary-jvm.
---

# binary-cpp project workflow

Documentation: miniwiki project `bncpp` (skill `miniwiki-api`); backlog: minitick project `bncpp` (skill
`minitick-api`); environment, commands and rules: `CLAUDE.md`. Generic Binary Ninja mechanics (`bnrun`
script bridge, usage lock, Personal-license workarounds): skill `binaryninja-bridge`.

## Workflow per ticket
1. `minitick get -p bncpp N --expand comment`; set it IN PROGRESS (`minitick update -p bncpp N -f
   status="IN PROGRESS"`). Wiki: `miniwiki …`. Both CLIs find their servers through `MINITICK_URL` /
   `MINIWIKI_API_URL` from the shell profile (set up per machine); if the Bash tool's shell lacks them, use
   `http://musicmac.local:8000` / `:8001` -- never a numeric LAN address (musicmac's Wi-Fi one rotates).
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
- Landing pads are separate functions in BN, and some are in no function at all: `cpp/landing_pads.py` creates
  them (command, `bn_landing_pads.py`; `bn_dump.py` does it in its views). Never automatically on load (bncpp-4).
- Shared code (`shared/`): no imports from `cpp/`, hooks for language specifics, provenance header, row in the
  wiki `code-structure.md` table; mirror the split in binary-jvm (jvm-68, bncpp-14).
- MLIL's register view can lie: after a load MLIL folded away (`lea r15, [rbp-0x50]`) `get_var_for_reg` and the
  MLIL instruction's `get_reg_value` still say r15's entry value (bncpp-155) -- check with
  `Function.get_reg_value_at` (`_holds` in `cpp/pseudo_cpp.py`). BN also types unpassed tail parameters as stack
  variables, so "map by storage" fails there (bncpp-152).
- Probe scripts through the bridge: drop every Function reference and `gc.collect()` before `bv.file.close()`, and
  keep an exception from holding them (format it as text first) -- the BNFreeFunction crashes (bncpp-102, -168).

## Gotchas: classes and databases (details: wiki `classes.md`)
- BN 6.1 resolves Mach-O binds through the nlist names: where an obfuscator hashed them (SynthV), the typeinfo
  vptr binds and some imports are gone and BN's RTTI finds 0 vtables (bncpp-25). `cpp/rtti.py` falls back to the
  layout; check any change with `tests/ref_class_scan.py --compare` (0 missing, structure ≤ 2 on SynthV).
- `f.has_user_type` is True for every function of any `.bndb` that went through a database round trip, though
  nobody set types (a BN bug, bncpp-29, `tests/repro_user_types/`; analysis still re-infers them): protect only types
  that differ from BN's fresh inference (`bn_class_types.py` `BASELINE` / `DUMP_TYPES`).
- A named type reference (a data var's type) has no `.members`: resolve it (`bv.get_type_by_name`).
- `C:` comments inside a function are function-level (`f.get_comment_at(addr)`), as in the bridge's annotate.py;
  `bv.get_comment_at` / `bv.address_comments` / `f.comment` don't see them -- verify with the right one.
- Once a variable has a struct type, BN lifts stores through it as `MLIL_STORE_STRUCT` (`this->vptr = …`), not
  `MLIL_STORE`: match both, or a pass breaks on already-typed views (O0 suite, SynthV's virtual dtors).
- BN reports a class's field accesses for every class of its chain (`get_code_refs_for_type_field` on a base
  lists the derived and sibling classes' too): cap a base by its derived classes' sizes; field passes run to a
  fixpoint (a second APPLY must change nothing).
- Closure targets (std::function lambdas, function objects) are classes to RTTI: `TypeInfo.closure` (set by
  `rtti.scan`, `cpp/rtti_closures.py`) tells them apart by the family; the LSDA's catch types veto exception
  families -- BN names those entries `typeinfo_for_X` (resolve through `BNImage.symbol_keys`).
- In shell heredocs that carry Markdown, quote the delimiter (`<<'EOF'`) -- or the backticks run as commands.
