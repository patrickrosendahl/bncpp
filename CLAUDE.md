# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

**Documentation lives in the miniwiki project `bncpp`, the work backlog in the minitick project `bncpp`.** The
repo holds only code, this file and the skills -- no README, design notes or TODO files. Start with
`miniwiki cat bncpp/index.md` and `minitick query -p bncpp 'not status in ("RESOLVED", "MERGED", "REJECTED")' --full --fields title,status,priority`.
New findings go into the wiki, new work into tickets.

## What this is

A Binary Ninja plugin for readable C++: a **"Pseudo Cpp"** language view (try/catch from the compiler's
exception tables, readability passes on HLIL). The repo root is the plugin package; it is linked into
`~/Library/Application Support/Binary Ninja/plugins/binary-cpp`. Sister project of
**`/Users/patrick/dev/binary-jvm`** (wiki / minitick `jvm`): before writing something, read its equivalent (wiki
`reuse-from-binary-jvm.md`) and its gotchas (binary-jvm `CLAUDE.md`, `skills/jvm/SKILL.md`); do not copy JVM
specifics. Language-neutral code goes into `shared/` (rules + shared-file table: wiki `code-structure.md`).

## Commands

```bash
python3 tests/suite/suite.py build                     # tests/suite/src/TestX.cpp -> bin/<arch>-O<n>/TestX.dylib
B=/Users/patrick/dev/bn-script-bridge/bnrun
$B --timeout 60 tests/bn_dev_load.py                   # register "Pseudo Cpp devN" (BN can't unregister)
$B --parallel --timeout 600 tests/bn_dump.py           # .scratch/suite/out/<variant>/TestX.{pcpp,pc,lsda}
                                                       #   only some: --env DUMP_KINDS=lsda (comma list),
                                                       #   --env DUMP_TESTS=TestVirtual (name prefixes)
python3 tests/suite/suite.py compare [--diff] [TestX…] # against tests/suite/results/ (exit 1 on a difference)
python3 tests/suite/suite.py check [--worst N] [K=V…]  # no-loss vs Pseudo C + flaw counters (exit 1: a gate)
python3 tests/suite/suite.py accept TestX…             # reviewed output -> reference
python3 tests/suite/suite.py ref-lsda                  # offline reference decode -> .scratch/suite/ref/
python3 tests/suite/suite.py crosscheck [--diff]       # BN .lsda vs offline, names masked (exit 1: structure)
$B --parallel --timeout 600 [--env CREATE_PADS=1] tests/bn_eh_survey.py   # landing pads / lost code per owner
# classes (wiki classes.md): scan, names, types -- dry runs write .scratch/classes/<bin>.{names,types}.review
$B --bndb BIN --timeout 300 tests/bn_class_scan.py     # -> .scratch/classes/<bin>.bn.classes
python3 -I tests/ref_class_scan.py BIN --compare .scratch/classes/<bin>.bn.classes   # vs the file (exit 1: structure)
$B --bndb DB --timeout 600 [--env APPLY=1] tests/bn_class_apply.py          # names (R:/D:/C: directives)
$B --bndb DB --timeout 1800 --env BASELINE=F [--env APPLY=1] tests/bn_class_types.py   # structs + 'X* this'
$B --bndb DB --timeout 1800 --env BASELINE=F [--env NAMES=F] [--env APPLY=1] tests/bn_class_fields.py  # sizes, bases, fields
$B --bndb DB --timeout 900 tests/bn_vcall_count.py     # HLIL indirect / named vptr calls (a sample)
# native part (C++, native/): API checkout /Users/patrick/dev/binaryninja-api on the branch matching the app's
# Contents/Resources/api_REVISION.txt (bn-<build>); loads only on a BN restart, no dev loads
cmake -S native -B native/build -DCMAKE_BUILD_TYPE=Release && cmake --build native/build -j
#   installed once as a symlink (BN loads native plugins only from the plugins folder's top level):
#   ln -s "$PWD/native/build/out/libbncpp_native.dylib" ~/Library/Application\ Support/Binary\ Ninja/plugins/
```
Details and the suite layout (Fernflower style): wiki `testing.md`.

## Environment (this machine)

- **Binary Ninja 6.1**, **Personal license = no headless API**: all testing happens in the running GUI through
  the `bnrun` bridge (skill `binaryninja-bridge`). Always pass `--timeout N`; serialized lane for
  dev loads, `--parallel` for scripts on their own views. Restart BN only with the user's OK (`bnrestart`) --
  the installed plugin only reloads on restart, so iterate with dev loads.
- Grep the installed API source before using a new call:
  `/Applications/Binary Ninja.app/Contents/Resources/python/binaryninja/`.
- Apple clang (Itanium ABI, Mach-O); the shell may run under Rosetta, so builds pass `-arch`. No MSVC.
- More: wiki `environment.md`.

## Skills

`skills/` is tracked; `.claude/` is git-ignored and Claude Code finds the skills through a local symlink -- after
a fresh clone run `mkdir -p .claude && ln -s ../skills .claude/skills`. `skills/bncpp` is the project skill (load
it); `minitick-api`, `miniwiki-api`, `binaryninja-bridge` and `jvm` (the sister project's skill, for reference) are
relative links into the sibling repos.

## How to work

- **One thing at a time, in the foreground**: no background agents, no parallel BN runs (heavy scripts next to
  each other time out).
- Measure first; one commit per ticket, with the before/after numbers in a ticket comment; finished tickets go
  to RESOLVED with a verification comment (no reviewer).
- Never lose code: a rendering failure prints the original HLIL as a comment (`emit_error`).
- **Binary Ninja is the source of truth** for everything format-specific (sections, symbols, imports, its
  native RTTI results): decoders read through `cpp/bnimage.py`. Own file parsers (`cpp/macho.py`,
  `tests/ref_*.py`, `suite.py ref-lsda`) are reference only -- cross-checks and bug-report evidence.
- `sample/synthv/` (git-ignored): scratch copy of the Synthesizer V slices + synVbasic's `.bndb` (state in its
  `PROVENANCE.txt`). Break it freely; findings go to the synVbasic session (`synthv`) as messages. Commercial
  binary -- never commit.
- **The BN app is shared** (synthv, binary-jvm): warn before heavy runs; one handle per `.bndb` -- another
  session's database changes only through its own lane (dry run + review files first, then they run it);
  `--bndb-save` / `--bndb-close` only with a PATH.
- External documentation (ABI specs, LSDA format, MSVC EH) is linked or attached on wiki `references.md`.
- Ask before restarting Binary Ninja.

## Git / remote

- Remote `origin` (Gitea on the LAN): `ssh://git@mackup.local:222/patrick/binary-cpp.git`
  (web: <http://mackup.local:3000/patrick/binary-cpp>), default branch `main`, public like binary-jvm.
- Second remote `github` = `git@github.com:patrickrosendahl/bncpp.git` (as binary-jvm, 2026-10-14); push `main` to
  both (`git push origin main && git push github main`).
- Gitea API token: `~/.config/gitea-token` (`Authorization: token …`, `http://mackup.local:3000/api/v1`);
  push-to-create is disabled on the server, so new repos go through `POST /api/v1/user/repos`.
- Gitea sometimes sleeps; if a push hangs, the host (`mackup.local`) or the service may be down -- retry shortly.
