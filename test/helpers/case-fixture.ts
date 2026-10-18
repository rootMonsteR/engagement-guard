import { copyFile, mkdir, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runEngagementCommand } from '../../src/engagement/commands.js'
import { recordFirstRunAck } from '../../src/first-run.js'
import { resolvePaths } from '../../src/paths.js'
import type { LookupFn } from '../../src/scope/resolver.js'
import { FIXTURES, fakeLookup, IN_WINDOW } from '../policy/guard-helpers.js'

export const TABLE_CASE_ID = 'acme-table-2026q4'
export const EXPLOIT_CASE_ID = 'acme-table-exploit-2026q4'

const CASES = {
  default: { file: 'table-case.yaml', id: TABLE_CASE_ID },
  exploit: { file: 'table-case-exploit.yaml', id: EXPLOIT_CASE_ID },
} as const

export interface ActiveCase {
  /** A temp workspace whose `.guard/engagement.yaml` is the table case, attested and frozen. */
  cwd: string
  /** A temp home with the first-run acknowledgement recorded for `alice`. */
  home: string
  /** The frozen case's id. */
  caseId: string
  now: () => Date
  lookup: LookupFn
  cleanup(): Promise<void>
}

/**
 * A table case (`fixtures/engagements/table-case.yaml`, or the exploit variant) as an active case
 * in a fresh workspace: copied to `<cwd>/.guard/engagement.yaml`, the first-run acknowledgement
 * recorded in `home`, and the case frozen with `engagement freeze --attest`. The clock is
 * `IN_WINDOW`.
 */
export async function activeCase(
  opts: { home?: string; which?: keyof typeof CASES; freeze?: boolean } = {},
): Promise<ActiveCase> {
  const fixture = CASES[opts.which ?? 'default']
  const cwd = await mkdtemp(join(tmpdir(), 'guard-case-'))
  const home = opts.home ?? (await mkdtemp(join(tmpdir(), 'guard-home-')))
  const paths = resolvePaths({ home, env: {} })
  const now = () => IN_WINDOW
  await mkdir(join(cwd, paths.dirName), { recursive: true })
  await copyFile(
    join(FIXTURES, 'engagements', fixture.file),
    join(cwd, ...paths.engagementPath.split('/')),
  )
  await recordFirstRunAck(home, 'alice', IN_WINDOW)
  if (opts.freeze !== false) {
    const r = await runEngagementCommand(['freeze', '--attest', fixture.id], {
      cwd,
      home,
      interactive: false,
      now,
    })
    if (r.exitCode !== 0) throw new Error(`fixture freeze failed: ${r.output}`)
  }
  return {
    cwd,
    home,
    caseId: fixture.id,
    now,
    lookup: fakeLookup,
    async cleanup() {
      await rm(cwd, { recursive: true, force: true })
      if (opts.home === undefined) await rm(home, { recursive: true, force: true })
    },
  }
}
