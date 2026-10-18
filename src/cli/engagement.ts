import { createGuard } from '../guard.js'
import { guardOptions, refuseWithoutTerminal, writeLine } from './args.js'
import type { CliIo } from './main.js'

/** The subcommands that write or attest a case: refused without an interactive terminal. */
const MUTATING = new Set(['new', 'freeze', 'edit', 'load'])

/**
 * `engagement-guard engagement <validate|show|freeze|edit|load|new> …`, non-interactive, through
 * a guard over the workspace so that freeze, edit and load are written to the audit chain.
 * `new`, `freeze`, `edit` and `load` are refused, before anything is opened or written, when the
 * CLI is not run from an interactive terminal.
 */
export async function runEngagement(args: string[], io: CliIo): Promise<number> {
  const sub = args[0]
  if (sub !== undefined && MUTATING.has(sub) && refuseWithoutTerminal(io, `engagement ${sub}`)) {
    return 1
  }
  const guard = await createGuard(guardOptions(io, { cwd: io.cwd }))
  try {
    const r = await guard.engagement(args)
    writeLine(io.stdout, r.output)
    return r.exitCode
  } finally {
    await guard.dispose()
  }
}
