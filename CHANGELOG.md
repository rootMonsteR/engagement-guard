# Changelog

## 0.1.0 — 2026-10-18

Extracted from the security layer (`packages/sec`) of the authors' Nemesis project, snapshot of
2026-10-18 (a merge of its `task/p13` and `task/p11` branches), as a standalone package.

- Library: `createGuard()` over an engagement file, a scope engine with DNS guard rails, a shell
  target extractor with a known-tools table, a fail-closed decision matrix and a hash-chained
  audit log; `check`, `checkRequest`, `middleware` and `install` for a harness with a permission
  engine, `subscribe` for its events. A disposed guard refuses further checks.
- CLI `engagement-guard`: `init`, `engagement validate|show|freeze|edit|load`, `ack`,
  `check` (exit 0 pass, 1 ask, 2 deny), `hook` (Claude Code `PreToolUse`), `audit verify|show|export`.
  `ack`, `init` and `engagement new|freeze|edit|load` refuse to run without an interactive
  terminal: a case is attested by a person, not by an agent. Freeze, edit and load from the CLI
  are written to the audit chain.
- Claude Code hook: inspects `Bash`, `Write`, `Edit`, `MultiEdit` and `NotebookEdit` by default and
  any tool named with `--tool`; fails closed (deny JSON, stderr reason, exit 2) on a malformed
  payload, a `Bash` call without a command, an internal error or a decision that outlives
  `--timeout-ms` (default 20 s); resolves the case from `CLAUDE_PROJECT_DIR` when set.
- Policy added beyond the Nemesis snapshot, from the adversarial review: a shell or interpreter
  fed its program through a pipe, a `<` redirect, `-s`/`-`, an encoded PowerShell command, inline
  code that decodes or executes data, or a script written earlier in the same command now asks
  `OPAQUE_CONSTRUCT`; a substitution on an interpreter segment asks; the guard's own `ack`,
  `init` and `engagement new|freeze|edit|load`, run from a shell by any launcher, are denied
  `PROTECTED_PATH`. Pinned by 25 new rows of the extraction table (209 rows).
- Audit chain lock (`createAuditLog({ lock: true, lockTimeoutMs })`) so several processes can
  append to one chain; appends refresh from the chain tail; a stale lock is renamed before it is
  taken over; the shared `index.jsonl` is written under the audit-root lock.
- `createGuard` refuses a workspace directory that does not exist, so a hook or CLI call with a
  wrong `cwd` fails closed instead of creating an audit log there.
- Product-neutral names: `.guard/` workspace directory, `GUARD_HOME` (default
  `~/.engagement-guard`), `GUARD_OPERATOR`, `annotations.guard`, `engagement-guard engagement edit`
  as the attestation hint; a custom `dirName` and `commandHint` reach every message.
- The audit chain's genesis label is `guard-audit-v1`; logs written by Nemesis's layer
  (`nemesis-audit-v1`) do not verify under this package.
- The first-run statement (`first-run-v1`) describes this library; no acknowledgement given to
  another product carries over.
- Not published on npm yet: install from a clone (`pnpm build && npm install -g .`).
