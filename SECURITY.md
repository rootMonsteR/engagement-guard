# Security policy

engagement-guard is a control: it decides whether an agent's command or tool call may run. A flaw in it is a security vulnerability, not an ordinary bug, and is handled privately until a fix is released.

## Supported versions

Only the latest release line (currently 0.1.x) receives fixes.

## What counts as a vulnerability

- **A bypass.** A shell command or tool call that reaches a target outside the engagement's scope, runs outside the window or inside a blackout, or runs without an attested case, and gets `pass` or `ask` where `docs/decision-matrix.md` says `deny`. This includes tricks of quoting, encoding, substitution, wrappers, interpreters, target-list files and name resolution.
- **A false pass on protected paths.** A command or file-tool call that alters the case file, the frozen scope snapshots, the audit log, or the acknowledgement and keys without a `deny`.
- **Agent self-attestation.** Any way for an agent, rather than a person at a terminal, to run `ack`, `init` or `engagement new|freeze|edit|load`.
- **Audit integrity.** A record that can be altered, removed, reordered or forged without `engagement-guard audit verify` reporting it, or a decision that is returned before it is written.
- **Secret leakage.** A credential that reaches the audit log unredacted.
- **Hook fail-open.** A way to make the Claude Code hook crash, hang past its timeout, or exit with a non-blocking status so that the tool runs.

The Honest limits section of the README lists what the guard does not attempt (for example, it reads commands, not packets). Those are documented limits, not vulnerabilities. A report that shows one of them is exploitable in a way the README does not describe is still welcome.

## How to report

Do not open a public issue for a bypass or any of the above. Report it privately through GitHub's private vulnerability reporting:

https://github.com/rootMonsteR/engagement-guard/security/advisories/new

Include:

- the exact command or tool call, and the harness it came from (CLI `check`, the Claude Code hook, the library, the MCP example);
- the engagement file, using only RFC 5737 or RFC 3849 addresses and `.example` names;
- the decision you got and the one the decision matrix says you should have got;
- the package version, operating system and Node version.

The most useful form of a report is a failing row for `test/fixtures/commands/extraction-table.yaml`; the existing rows show the format.

## What to expect

This package is maintained by one person. You will get an acknowledgement within seven days and an assessment within fourteen. A confirmed bypass is fixed in a patch release and pinned by a new row in the extraction table, so it cannot return silently. The advisory is published with the fix, with credit to the reporter unless they ask otherwise.

## Scope of this policy

The policy covers the code in this repository and the package published from it. It does not cover the tools the guard wraps, the agent harnesses that call it, or the engagement files users write.
