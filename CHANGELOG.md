# Changelog

## 0.1.1 — 2026-10-20

Fixes from the pre-release and first public reviews, and the packaging work for the npm
release. No reason code, audit record field, exit code or hook output changed.

- From the pre-release review of 2026-10-19: the attestation commands are denied by any launcher,
  wrapper, runtime or inline script that names the binary (`npm exec`, `yarn`, `pnpm`,
  `npx -p`, `bun run`, `deno run`, `node --import`, `unbuffer`, `expect -c`, `pty.spawn`);
  a link to the case directory or an ancestor (an alias for a later write), an editor saving
  the case file, `find -delete` or `find -exec <writer>` under a start directory that holds it,
  a `git checkout`/`restore` pathspec over it, and a remote-name download (`curl -O`, `wget`)
  into it are `PROTECTED_PATH`. Pinned by 34 new rows (243 rows).
- From the public review of 2026-10-19: `SECURITY.md` (private vulnerability reporting) and
  issue templates; the README explains the `§` and `P`-numbered references to the unpublished
  Nemesis design documents; the test count is given for Windows and Linux.
- Packaging: `prepublishOnly` runs `pnpm check && pnpm build`, so a publish cannot ship a stale
  or untested `dist/`. The declaration file starts with `/// <reference types="node" />` and
  `@types/node` is an optional peer dependency, because the public types name
  `NodeJS.ProcessEnv` and `Buffer` and TypeScript 7 no longer includes every `@types` package by
  default: a consumer with `@types/node` installed compiles without a `types` entry in its
  tsconfig. The README states that the package is ESM only.
- MCP server example: `ExecEvents.emit` takes a distributive omit of `GuardEvent`, so the
  example typechecks (an `Omit` over the union dropped `execId`).
- The extraction-table row for `find … -delete` starts at a subdirectory of the workspace
  instead of `/tmp`, so the suite passes from a clone under `/tmp`, where `/tmp` was an ancestor
  of the fixture's `.guard` and the guard rightly denied the row. (`/var/log` was not an option:
  deleting under it is the log-wiping `HARD_REFUSAL`.)

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
  `PROTECTED_PATH`. Pinned by 25 new rows of the extraction table.
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
- Source release on GitHub (tag `v0.1.0`); not on npm.
