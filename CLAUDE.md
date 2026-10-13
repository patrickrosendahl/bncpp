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
python3 tests/suite/suite.py lsda                      # offline (no BN): decoded exception tables -> TestX.lsda
B=/Users/patrick/dev/bn-script-bridge/bnrun
$B --timeout 60 tests/bn_dev_load.py                   # register "Pseudo Cpp devN" (BN can't unregister)
$B --parallel --timeout 600 tests/bn_dump.py           # .scratch/suite/out/<variant>/TestX.{pcpp,pc} (~6.5 min)
python3 tests/suite/suite.py compare [--diff] [TestX…] # against tests/suite/results/ (exit 1 on a difference)
python3 tests/suite/suite.py accept TestX…             # reviewed output -> reference
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
a fresh clone run `mkdir -p .claude && ln -s ../skills .claude/skills`. `skills/cpp` is the project skill (load
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
  `tests/ref_*.py`, for now also `suite.py lsda`) are reference only -- cross-checks and bug-report evidence.
- `sample/synthv/` (git-ignored): scratch copy of the Synthesizer V slices + synVbasic's `.bndb` (2026-10-13).
  Break it freely; findings go to the synVbasic session as messages. Commercial binary -- never commit.
- External documentation (ABI specs, LSDA format, MSVC EH) is linked or attached on wiki `references.md`.
- Ask before restarting Binary Ninja.

## Git / remote

- Remote `origin` (Gitea on the LAN): `ssh://git@mackup.local:222/patrick/binary-cpp.git`
  (web: <http://mackup.local:3000/patrick/binary-cpp>), default branch `main`, public like binary-jvm. No GitHub mirror (binary-jvm has one) -- the user's
  decision, 2026-10-08; don't add one unless asked.
- Gitea API token: `~/.config/gitea-token` (`Authorization: token …`, `http://mackup.local:3000/api/v1`);
  push-to-create is disabled on the server, so new repos go through `POST /api/v1/user/repos`.
- Gitea sometimes sleeps; if a push hangs, the host (`mackup.local`) or the service may be down -- retry shortly.
