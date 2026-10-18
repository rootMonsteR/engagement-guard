import type { Readable } from 'node:stream'
import type { EngagementCommandContext } from '../engagement/commands.js'
import type { CreateGuardOptions } from '../guard.js'
import { resolvePaths } from '../paths.js'
import type { CliIo } from './main.js'

/** Reads one line from `stdin` (without its line ending); the rest of the stream is left unread. */
export async function readLine(stdin: Readable): Promise<string> {
  let buf = ''
  for await (const chunk of stdin) {
    buf += typeof chunk === 'string' ? chunk : (chunk as Buffer).toString('utf8')
    const nl = buf.indexOf('\n')
    if (nl !== -1) return buf.slice(0, nl).replace(/\r$/, '')
  }
  return buf.replace(/\r$/, '')
}

/** Writes `text` to `w` with exactly one trailing newline. */
export function writeLine(w: { write(s: string): unknown }, text: string): void {
  w.write(text.endsWith('\n') ? text : `${text}\n`)
}

/**
 * True (and the refusal written to stderr) when `command` changes or attests a case but the CLI
 * is not run from an interactive terminal: an agent must not acknowledge, scaffold, freeze, edit
 * or load a case through the guard's own CLI. The caller then exits 1 with nothing written.
 */
export function refuseWithoutTerminal(io: CliIo, command: string): boolean {
  if (io.tty) return false
  writeLine(
    io.stderr,
    `refused: ${command} needs an interactive terminal; a case is attested by a person, not by an agent`,
  )
  return true
}

/** The options every CLI-built guard shares: the workspace, the environment, the audit lock. */
export function guardOptions(
  io: CliIo,
  over: Partial<CreateGuardOptions> & { cwd: string },
): CreateGuardOptions {
  return {
    env: io.env,
    lock: true,
    ...(io.now === undefined ? {} : { now: io.now }),
    ...(io.lookup === undefined ? {} : { lookup: io.lookup }),
    ...over,
  }
}

/** The context the `engagement` command family runs with from the CLI (never interactive). */
export function commandContext(io: CliIo): EngagementCommandContext {
  const paths = resolvePaths({ env: io.env })
  return {
    cwd: io.cwd,
    interactive: false,
    home: paths.home,
    paths,
    ...(io.now === undefined ? {} : { now: io.now }),
  }
}
