# engagement-guard

engagement-guard decides whether a shell command or a network tool call is authorised by an engagement file, and records every decision in a hash-chained audit log. It sits between an AI agent and the security tools the agent runs. The engagement file sets the scope, the time window, the blackout hours and the rules of engagement. The guard reads each command, extracts its targets, and passes, asks or denies. Why this matters: in an incident report dated 5 August 2026 the UK AI Security Institute counted 19 unsanctioned actions in 10 of 122 cyber-evaluation runs across seven frontier models, in a setup that deliberately allowed open internet access; its fixes are fine-grained network controls and monitoring that blocks out-of-scope actions as a run proceeds. This package is the second kind of fix, for any agent harness: a TypeScript library, a CLI, a Claude Code hook and an MCP server example.

## Install

The package is not on npm yet, so `npm install -g engagement-guard` and `npx engagement-guard` do not resolve to this code until the authors publish it; until then install from a clone and point hooks at the installed binary or an absolute path:

```sh
git clone <this repository> engagement-guard && cd engagement-guard
pnpm install && pnpm build
npm install -g .          # provides the `engagement-guard` command
```

## Sixty seconds

This is a real run of the CLI. It uses a scratch workspace and a scratch `GUARD_HOME`. The window brackets the time of the run. Paths inside the workspace are shown as `<demo>`. The operator statement printed by `ack` is left out here; read it in full when you run `ack`. `init`, `ack` and `engagement freeze|edit|load` must be typed at a terminal: run without one (piped, or by an agent) they refuse, and the guard denies them when it sees them in a shell command.

```sh
pnpm build
export GUARD_HOME="$(mktemp -d)"
cd "$(mktemp -d)"            # the workspace, outside the repo: shown as <demo> below
alias engagement-guard="node /path/to/engagement-guard/dist/cli/bin.js"
```

```text
$ engagement-guard init --id demo-2026q4 --name Demo --client "Demo Ltd" --in 192.0.2.0/24 --out 192.0.2.66 --window-start 2026-10-17T19:02:38Z --window-end 2026-10-19T19:02:38Z --timezone UTC --auth-ref SOW-1 --authorised-by "Dana Reyes" --signed-on 2026-10-10
wrote <demo>\.guard\engagement.yaml
next: replace every TODO, then run: engagement-guard engagement validate
# exit code 0

$ engagement-guard engagement validate
valid: demo-2026q4 (0 warnings)
# exit code 0

$ engagement-guard ack --operator alice
[the first-run-v1 operator statement is printed here]
Type I AGREE to acknowledge: I AGREE
acknowledged: alice at 2026-10-18T19:02:38.776Z (first-run-v1 65fcc27572cf)
# exit code 0

$ engagement-guard engagement freeze --attest demo-2026q4
frozen: demo-2026q4 scope_hash bec26bff59783d9969cba8f353aaa78490aa412ee82c19b1a391c24f618bf94a
status: active — demo-2026q4 (scope_hash bec26bff5978)
# exit code 0

$ engagement-guard check "nmap 192.0.2.10"
pass IN_SCOPE
engagement-guard: PASS [IN_SCOPE]: all targets are in scope; tier and rate are within the RoE
Target: 192.0.2.10: in-scope, rule in[0]: 192.0.2.0/24
Tier: recon
Case: demo-2026q4 (<demo>\.guard\engagement.yaml)
Core permission rules decide next.
targets: 192.0.2.10 (in-scope)
# exit code 0

$ engagement-guard check "nmap 203.0.113.5"
ask UNKNOWN_TARGET
engagement-guard: NEEDS CONFIRMATION [UNKNOWN_TARGET]: a target matches no scope entry
Target: 203.0.113.5: unknown, no matching scope rule
Tier: recon
Case: demo-2026q4 (<demo>\.guard\engagement.yaml)
The operator must confirm; if the target belongs to the engagement, add it with `engagement-guard engagement edit`.
targets: 203.0.113.5 (unknown)
# exit code 1

$ engagement-guard check "nmap 192.0.2.66"
deny OUT_OF_SCOPE
engagement-guard: DENIED [OUT_OF_SCOPE]: a target is out of scope
Target: 192.0.2.66: out-of-scope, rule out[0]: 192.0.2.66
Tier: recon
Case: demo-2026q4 (<demo>\.guard\engagement.yaml)
If the client has authorised this, the operator can update `.guard/engagement.yaml` and run `engagement-guard engagement edit` (audited). Do not try to work around this check.
targets: 192.0.2.66 (out-of-scope)
# exit code 2

$ engagement-guard check "echo bm1hcCAxOTIuMC4yLjY2 | base64 -d | sh"
ask OPAQUE_CONSTRUCT
engagement-guard: NEEDS CONFIRMATION [OPAQUE_CONSTRUCT]: the command uses constructs the guard cannot read
Targets: none extracted
Opaque constructs: piped-code
Case: demo-2026q4 (<demo>\.guard\engagement.yaml)
Write the targets literally, or the operator must confirm.
# exit code 1

$ engagement-guard audit verify
ok demo-2026q4/37fc48ef-39ab-4c99-993a-ef796fc6298d.jsonl 2 e98bb87fce7e
ok demo-2026q4/9bcf0fbb-56a2-453b-b5aa-03c095dab693.jsonl 3 6705118ec282
ok demo-2026q4/307dadca-5576-4a3d-a393-74c9b01f4c0b.jsonl 3 285b1f400c0a
ok demo-2026q4/9dfc81cb-727a-4571-8f4c-f1958aa69e02.jsonl 2 3248fe68ecad
ok demo-2026q4/7becbe09-0f23-44f9-b0ba-d7c6d50d4cf0.jsonl 3 0d8510a8966e
# exit code 0
```

`203.0.113.5` is in no scope list, so the guard asks. `192.0.2.66` is listed under `out`, so it denies. A command decoded into a shell cannot be read, so it asks (`OPAQUE_CONSTRUCT`, with the construct named). Each CLI call, the freeze included, runs as its own audit session, which is why `audit verify` lists five chains. `check` exits 0 for a pass or a call it does not inspect, 1 for an ask and 2 for a deny. Run `engagement-guard --help` for every command.

## Claude Code hook

`engagement-guard hook` is a Claude Code `PreToolUse` hook. It checks each `Bash` command, and each `Write`, `Edit`, `MultiEdit` and `NotebookEdit` against the protected case paths, before the call runs, and answers `deny` or `ask`, or stays silent on a pass. Other tools are inspected when named with `--tool` and listed in the matcher.
A hook ask forces a prompt even in auto mode, but Claude Code has no unskippable ask, so an exploitation-tier confirmation arrives as an ask whose reason starts `[cannot be auto-approved]`.
Any failure on the way to a decision, a malformed payload or a decision that outlives `--timeout-ms` becomes a `deny` with `GUARD_ERROR` on stdout and stderr with exit 2, because a crashed or timed-out hook would let the call run.

Setup, sample output and limits: [examples/claude-code/README.md](examples/claude-code/README.md).

## MCP server example

An example MCP server with a `guarded_shell` tool: it runs a command only when `guard.check` passes, and returns the decision text otherwise. It also offers `engagement_status`.
It is an example, not a published package: [examples/mcp-server/README.md](examples/mcp-server/README.md).

## Library

`createGuard(options)` opens the workspace's case and audit log and returns a `Guard`:

- `guard.check(command)` decides a shell command and audits the decision. It resolves to an outcome (`verdict`, `reason`, `message`, `annotation`) or to `'not-inspected'`. `guard.checkRequest(req)` does the same for any request, structured network tools included.
- `guard.middleware` is a `before-rules` permission middleware for a harness with its own permission engine. `guard.install(host)` registers it on a host with a `use(mw, stage)` method and returns the remover.
- `guard.subscribe(events)` routes a harness's events (`exec.spawn`, `exec.exit`, `tool.result`, …) into the audit log.
- `guard.dispose()` removes every middleware and subscription and flushes the audit log.

```ts
import { createGuard } from 'engagement-guard'

const guard = await createGuard({ cwd: '/work/acme' }) // reads /work/acme/.guard/engagement.yaml
try {
  const out = await guard.check('nmap -sV 192.0.2.66')
  if (out === 'not-inspected') console.log('not a shell or network call')
  else console.log(out.verdict, out.reason) // against the demo case above: deny OUT_OF_SCOPE
} finally {
  await guard.dispose()
}
```

The home (first-run acknowledgement and signing key) is `options.home`, else `GUARD_HOME` from `options.env`, else `~/.engagement-guard`. The guard never reads `process.env` on its own. Everything else the package exports (the scope engine, the extractor, the audit verifier and exporter) is listed in `src/index.ts`.

## How a decision is made

The guard applies its checks in this order:

1. **Denylist.** Every shell command is checked against the hard denylist (DoS tools and flags, wipers, random or global targeting), in every case state. A hit is `HARD_REFUSAL`. A write to the case file, the scope snapshots, the audit log or the keys is `PROTECTED_PATH`.
2. **Case state and time.** First, commands that are not network actions, loopback-only targets, and fetch, VCS, package, DNS or remote-access use of trusted infrastructure pass to the harness's own rules. Then no usable case is a deny (`FIRST_RUN_REQUIRED`, `NO_ACTIVE_CASE`, `CASE_INVALID`, `NOT_ACKNOWLEDGED`, `SCOPE_TAMPERED`), and so are `OUTSIDE_WINDOW` and `BLACKOUT`. Nothing overrides the window or blackout hours.
3. **Scope classification.** Every target is classified against the case's `in`, `out` and operator lists, with DNS resolution checked too: out-of-scope, unknown, unresolvable, partly covered, trusted infrastructure or in scope.
4. **Tiers and rate.** The action's tier must be allowed by the rules of engagement, and its rate and timing flags must be within `rate_limits`. Authorised exploitation still needs the operator to confirm.
5. **Verdict.** Every matching row is collected. Deny beats ask-unskippable, which beats ask, which beats pass. Within one verdict, the first code in `REASON_CODES` wins.

A failure anywhere in the guard is `GUARD_ERROR`, and an audit log that cannot be written is `AUDIT_UNAVAILABLE`. Both deny. The full matrix and every reason code are in [docs/decision-matrix.md](docs/decision-matrix.md).

## Honest limits

The guard reads command text, not behaviour. It asks instead of guessing when the code a shell
or interpreter will run is not in the text: a substitution, a variable, an `eval`, a pipe or
redirect into a shell or interpreter, an encoded PowerShell command, inline code that decodes or
executes data, and a script written earlier in the same command. What it still cannot see passes
to the harness's ordinary rules: a script run with no visible target (`./scan.sh`, `python3 s.py`,
`make scan`, `npm run scan`), a case file rewritten by an interpreter (`python3 -c "open(…)"`),
`git checkout -- .guard`, an archive extracted into the workspace, or a download that picks its
own name after `cd .guard`. The guard denies its own attestation commands when an agent runs
them, but a person at a terminal can still attest a case the agent rewrote: read the diff
`engagement-guard engagement edit` shows before attesting. In Claude Code the hook can deny or
ask; a hook ask forces a prompt even in auto mode, but cannot be made unskippable. The audit
chain proves no post-hoc alteration without the signing key, not that the operator did not
rewrite the chain. A network-level egress control that does not read commands is the layer
below, and the configuration to rely on when compliance depends on it.

## Tests

The suite has 2,129 passing tests and 3 skipped (2,132 in all, run on 2026-10-18 after the final review and the follow-up fixes). The command extraction table in `test/fixtures/commands/extraction-table.yaml` (209 rows) runs each row through the extractor and the guard.

```sh
pnpm install
pnpm check      # biome lint, tsc typecheck, vitest
```

## Licence

Apache-2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE). The code was extracted from the security layer of the authors' Nemesis project.
