import type { Readable, Writable } from 'node:stream'
import { messageOf } from '../audit/util.js'
import type { LookupFn } from '../scope/resolver.js'
import { runAck } from './ack.js'
import { runAudit } from './audit.js'
import { runCheck } from './check.js'
import { runEngagement } from './engagement.js'
import { runHook } from './hook.js'
import { runInit } from './init.js'

/** What a CLI run reads and writes; tests pass in-memory streams. */
export interface CliIo {
  stdin: Readable
  stdout: Writable
  stderr: Writable
  cwd: string
  env: NodeJS.ProcessEnv
  /**
   * Whether stdin and stdout are both a terminal. Commands that attest or change a case (`ack`,
   * `init`, `engagement new|freeze|edit|load`) refuse without one: an agent drives the CLI through
   * pipes, and a case is attested by a person.
   */
  tty: boolean
  now?: () => Date
  lookup?: LookupFn
}

export type Command = (args: string[], io: CliIo) => Promise<number>

const COMMANDS: Record<string, { summary: string; run: Command }> = {
  init: {
    summary: 'Write .guard/engagement.yaml with TODO for every value not given',
    run: runInit,
  },
  engagement: {
    summary: 'validate | show | freeze | edit | load  (engagement-guard engagement --help)',
    run: runEngagement,
  },
  ack: { summary: 'Read the first-run statement and record your acknowledgement', run: runAck },
  check: {
    summary:
      'Decide a shell command against the case: check "<command>" [--cwd <dir>] [--shell posix|powershell] [--json]',
    run: runCheck,
  },
  hook: {
    summary:
      'Claude Code PreToolUse adapter: reads the hook JSON on stdin [--tool <name>]... [--shell …]',
    run: runHook,
  },
  audit: {
    summary:
      'verify [--case <id>] | show [--case <id>] [--tail <n>] | export [--case <id>] [--out <file>]',
    run: runAudit,
  },
}

export const USAGE = `Usage: engagement-guard <command> [options]

${Object.entries(COMMANDS)
  .map(([name, c]) => `  ${name.padEnd(12)}${c.summary}`)
  .join('\n')}

Exit codes of check: 0 pass or not inspected, 1 ask, 2 deny.
Environment: GUARD_HOME (default ~/.engagement-guard), GUARD_OPERATOR (default the OS user).
`

/** Runs one CLI invocation and resolves to its exit code; never throws. */
export async function runCli(argv: string[], io: CliIo): Promise<number> {
  const [name, ...rest] = argv
  if (name === undefined) {
    io.stderr.write(USAGE)
    return 1
  }
  if (name === '--help' || name === '-h' || name === 'help') {
    io.stdout.write(USAGE)
    return 0
  }
  const command = COMMANDS[name]
  if (command === undefined) {
    io.stderr.write(`unknown command '${name}'\n${USAGE}`)
    return 1
  }
  try {
    return await command.run(rest, io)
  } catch (err) {
    io.stderr.write(`engagement-guard ${name}: ${messageOf(err)}\n`)
    return 1
  }
}
