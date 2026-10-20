# engagement-guard as a Claude Code hook

Claude Code runs a `PreToolUse` hook before every tool call. With `engagement-guard hook`
registered for the `Bash` tool, every shell command Claude proposes is checked against the
workspace's engagement file before it runs, and every decision is written to the audit chain.
Registered for Claude Code's file tools as well, it stops Claude from rewriting the engagement
file, the audit log or the guard's keys with them. The hook can **deny** a call or turn it into
an **ask**; a pass stays silent so Claude Code's ordinary permission rules apply.

## Install

A hook that cannot start is non-blocking in Claude Code, so install the package and point the
hook at the installed binary rather than at `npx`, which may have to download first:

```sh
npm install -g engagement-guard        # provides the `engagement-guard` command used below
```

Add the hook to `.claude/settings.json` in the project (or to your user settings). The file in
this directory is the complete snippet:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "engagement-guard hook --tool WebFetch",
            "timeout": 60
          }
        ]
      }
    ]
  }
}
```

### Which tools are guarded

Two lists decide what is checked, and a tool is checked only if it is on **both**:

1. The `matcher` decides which tool calls Claude Code sends to the hook at all.
2. The hook inspects `Bash`, `Write`, `Edit`, `MultiEdit` and `NotebookEdit` by default, and any
   tool you add with `--tool <name>` (repeatable). Anything else it is sent, it lets through
   silently.

So `--tool WebFetch` does nothing unless the matcher also lists `WebFetch`, and a tool in the
matcher but not inspected by the hook is not checked either. With the snippet above:

- `Bash` commands are read as shell and checked against the case.
- `Write`, `Edit`, `MultiEdit` and `NotebookEdit` are checked for the file they write
  (`file_path`, or `notebook_path` for `NotebookEdit`): a write into `.guard/`, or into the
  guard home's `keys` or `first-run.json`, is denied with `PROTECTED_PATH`. Other files pass
  silently. A file-tool payload with no path is denied with `GUARD_ERROR`.
- `WebFetch` is checked as a network call: its input is swept for hosts and URLs.
- Everything else stays **unguarded**: MCP tools (`mcp__…`), `WebSearch` and any tool
  not in both lists. Add a tool to the matcher and to `--tool` to have its input swept the same
  way as `WebFetch`, or leave it out deliberately.

### Timeouts

A decision may look up host names (each lookup can take seconds under slow DNS) and wait for the
audit lock. Claude Code treats a hook that runs past its `timeout` as non-blocking, so the tool
would run. The hook therefore has its own deadline, `--timeout-ms <n>` (default `20000`): a
decision not made by then is denied with `GUARD_ERROR: decision timed out after <n> ms`. The
settings `timeout` is in **seconds** and must be comfortably larger than `--timeout-ms` (the
snippet uses 60 s against the default 20 s) so the hook's own deny always arrives first; if you
raise `--timeout-ms`, raise `timeout` with it.

## Set up the engagement (once per workspace)

```sh
engagement-guard init --id acme-ext-2026q4 --name "ACME external" --client "ACME Corp"
#   edit .guard/engagement.yaml: authorisation, window, scope in/out, rules of engagement
engagement-guard engagement validate
engagement-guard ack                                   # read the statement, type: I AGREE
engagement-guard engagement freeze --attest acme-ext-2026q4
engagement-guard engagement show
```

## What Claude sees

Ask Claude Code to scan a host that is **not** in scope:

> scan 203.0.113.5 with nmap

The hook answers with a `deny`; the command does not run and Claude is shown the decision text:

```
engagement-guard: DENIED [OUT_OF_SCOPE]: a target is out of scope
Target: 203.0.113.5: out-of-scope, rule out[0]: 203.0.113.0/24
Tier: recon
Case: acme-ext-2026q4 (<workspace>/.guard/engagement.yaml)
If the client has authorised this, the operator can update `.guard/engagement.yaml` and run `engagement-guard engagement edit` (audited). Do not try to work around this check.
```

A target the case does not mention, a partly authorised range, or a command the guard cannot
read (a variable, a substitution) becomes an **ask**: Claude Code prompts you, with the decision
text as the reason. An in-scope command prints nothing and goes through your normal permission
settings.

Afterwards:

```sh
engagement-guard audit show --tail 10
engagement-guard audit verify
```

## Limits worth knowing

- The hook can deny or ask, and a hook `ask` forces a prompt even in Claude Code's auto mode (the
  classifier may still deny, but it cannot approve silently). What the hook cannot do is mark an
  ask unskippable, so an exploitation-tier command the rules of engagement allow arrives as an ask
  whose reason starts `[cannot be auto-approved]`. How `bypassPermissions` treats a hook ask is not
  documented; anything that must never run has to be a deny, and the guard already denies a tier
  the rules of engagement do not allow.
- Only the `Bash` tool's commands are read as shell. Another tool named with `--tool <name>` is
  inspected as a network call: its input is swept for addresses, names and URLs and those are
  checked against the case, without knowing which program runs. Claude Code's Bash tool runs Git
  Bash on Windows, so commands are read as POSIX shell; pass `--shell powershell` only for a tool
  that really runs PowerShell.
- A hook that crashes is non-blocking in Claude Code. This hook catches every failure on the way
  to a decision and reports it as a `deny` with `GUARD_ERROR`, on stdout as JSON and on stderr
  with exit 2, so the command does not run. That includes a payload that has drifted from what
  the hook expects: a `Bash` call without a string `tool_input.command` is denied rather than
  passed. A crash before the hook starts (Node missing, `npx` unable to fetch the package) is
  outside its reach: install the package globally or point the hook at an absolute path so the
  start cannot fail. `npx` fetching the package also counts against the settings `timeout`.
- The case is resolved from `CLAUDE_PROJECT_DIR` when Claude Code sets it, so a `cd` into a
  subdirectory does not lose the engagement file; the command itself is still read relative to
  the hook's `cwd`.
- The guard reads command text, not behaviour. Commands built at run time are asked about, not
  understood. For compliance, put a network-level egress control underneath it.
