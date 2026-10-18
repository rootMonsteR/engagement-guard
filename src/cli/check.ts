import { resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { createGuard } from '../guard.js'
import type { GuardOutcome } from '../policy/guard.js'
import { guardOptions, writeLine } from './args.js'
import type { CliIo } from './main.js'

const USAGE =
  'Usage: engagement-guard check "<command>" [--cwd <dir>] [--shell posix|powershell] [--json]'

const SHELLS = ['posix', 'powershell'] as const
type Shell = (typeof SHELLS)[number]

const EXIT: Record<GuardOutcome['verdict'], number> = {
  pass: 0,
  ask: 1,
  'ask-unskippable': 1,
  deny: 2,
}

/** The decision as the CLI prints it: verdict and reason, the message, one line per target. */
export function formatOutcome(o: GuardOutcome | 'not-inspected'): string {
  if (o === 'not-inspected') return 'not-inspected'
  const targets = o.annotation.targets.map((t) => `targets: ${t.raw} (${t.class})`)
  return [`${o.verdict} ${o.reason}`, o.message, ...targets].join('\n')
}

/** The decision as `--json` prints it. */
export function outcomeJson(o: GuardOutcome | 'not-inspected'): string {
  if (o === 'not-inspected') return JSON.stringify({ verdict: 'not-inspected' })
  return JSON.stringify({
    verdict: o.verdict,
    reason: o.reason,
    message: o.message,
    targets: o.annotation.targets.map((t) => ({ raw: t.raw, class: t.class, rule: t.rule })),
  })
}

/**
 * Decides one shell command against the workspace's case and audits the decision. Exit 0 for
 * pass or not inspected, 1 for ask, 2 for deny.
 */
export async function runCheck(args: string[], io: CliIo): Promise<number> {
  let values: { cwd?: string; shell?: string; json?: boolean }
  let positionals: string[]
  try {
    ;({ values, positionals } = parseArgs({
      args,
      options: {
        cwd: { type: 'string' },
        shell: { type: 'string' },
        json: { type: 'boolean' },
      },
      allowPositionals: true,
      strict: true,
    }))
  } catch (err) {
    writeLine(io.stderr, `${(err as Error).message}\n${USAGE}`)
    return 1
  }
  const command = positionals.join(' ').trim()
  if (command === '') {
    writeLine(io.stderr, `check: a command is required\n${USAGE}`)
    return 1
  }
  const shell = values.shell ?? 'posix'
  if (!SHELLS.includes(shell as Shell)) {
    writeLine(io.stderr, `check: --shell must be one of ${SHELLS.join(', ')}\n${USAGE}`)
    return 1
  }
  const cwd = values.cwd === undefined ? io.cwd : resolve(io.cwd, values.cwd)
  const guard = await createGuard(guardOptions(io, { cwd, shell: shell as Shell }))
  try {
    const o = await guard.check(command)
    writeLine(io.stdout, values.json === true ? outcomeJson(o) : formatOutcome(o))
    return o === 'not-inspected' ? 0 : EXIT[o.verdict]
  } finally {
    await guard.dispose()
  }
}
