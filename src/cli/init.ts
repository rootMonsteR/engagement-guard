import { runEngagementCommand } from '../engagement/commands.js'
import { commandContext, refuseWithoutTerminal, writeLine } from './args.js'
import type { CliIo } from './main.js'

/** `engagement-guard init [--type …] [--profile …] [--id …] [--name …] [--client …] …`: a scaffold with TODOs. */
export async function runInit(args: string[], io: CliIo): Promise<number> {
  if (refuseWithoutTerminal(io, 'init')) return 1
  const r = await runEngagementCommand(['new', ...args], commandContext(io))
  writeLine(io.stdout, r.output)
  return r.exitCode
}
