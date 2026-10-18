import { homedir } from 'node:os'
import { join } from 'node:path'

/**
 * Every path and hint the guard uses, from one value (spec §4.2). The workspace paths are relative
 * to the workspace root, with `/` separators; `home` is absolute.
 */
export interface GuardPaths {
  /** The workspace directory holding the case, its snapshots and the audit log: `'.guard'`. */
  dirName: string
  /** `'.guard/engagement.yaml'` (relative to the workspace). */
  engagementPath: string
  /** `'.guard/audit'` */
  auditDir: string
  /** `'.guard/cases'` */
  casesDir: string
  /** `GUARD_HOME` or `~/.engagement-guard`: `first-run.json`, `keys/audit-ed25519.pem`. */
  home: string
  /** The command the operator runs to attest a scope change: `'engagement-guard engagement edit'`. */
  commandHint: string
}

export const DEFAULT_DIR = '.guard'
export const DEFAULT_COMMAND_HINT = 'engagement-guard engagement edit'
export const HOME_ENV = 'GUARD_HOME'
export const OPERATOR_ENV = 'GUARD_OPERATOR'

/**
 * The paths for a workspace directory name (`DEFAULT_DIR`) and a home: `opts.home`, else
 * `env[HOME_ENV]`, else `~/.engagement-guard`. Only the `env` passed in is read (none: `{}`).
 */
export function resolvePaths(
  opts: { home?: string; dirName?: string; commandHint?: string; env?: NodeJS.ProcessEnv } = {},
): GuardPaths {
  const dirName = opts.dirName ?? DEFAULT_DIR
  const fromEnv = opts.env?.[HOME_ENV]?.trim()
  const home =
    opts.home ??
    (fromEnv !== undefined && fromEnv !== '' ? fromEnv : join(homedir(), '.engagement-guard'))
  return {
    dirName,
    engagementPath: `${dirName}/engagement.yaml`,
    auditDir: `${dirName}/audit`,
    casesDir: `${dirName}/cases`,
    home,
    commandHint: opts.commandHint ?? DEFAULT_COMMAND_HINT,
  }
}
