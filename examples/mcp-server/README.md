# engagement-guard as an MCP server

A small Model Context Protocol server with two tools:

- `engagement_status` returns the status line of the case in the working directory.
- `guarded_shell { command, cwd? }` runs a shell command only when the guard passes it. A deny or
  an ask is returned as the decision text (as a tool error) and nothing runs. The decision, the
  spawn and the exit are written to the workspace's audit chain.

The guard logic is in `guarded-shell.ts` (no MCP dependency, covered by `server.test.ts` in the
root test suite); `server.ts` is the MCP wiring over stdio.

## Run

```sh
cd examples/mcp-server
pnpm install                 # installs engagement-guard from ../.. and the MCP SDK
pnpm typecheck
```

Set the engagement up in the directory the server will run from (see the root README: `init`,
`ack`, `engagement freeze`). Then point an MCP client at the server, for example in Claude Code's
`.mcp.json`:

```json
{
  "mcpServers": {
    "engagement-guard": {
      "command": "pnpm",
      "args": ["--dir", "examples/mcp-server", "start"]
    }
  }
}
```

Ask the client to run `guarded_shell` with `nmap 203.0.113.5` against a case that does not
include that address: the tool returns `DENY: engagement-guard: DENIED [OUT_OF_SCOPE] …` and no
process starts. An in-scope or local command runs and returns its exit code and output tails
(the last 8 KiB of each stream).

## Limits

The command runs through the platform shell (`/bin/sh -c`, or `cmd.exe /c` on Windows) with
the server's privileges; the guard decides whether it may start, nothing more. There is no
timeout and no sandbox in this example. The guard reads command text, not behaviour: a command
that builds its target at run time is asked about, not understood.
