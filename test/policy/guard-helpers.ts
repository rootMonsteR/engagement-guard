import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { parse as parseYaml } from 'yaml'
import type { AuditLog, AuditRecordInput } from '../../src/audit/writer.js'
import { type LoadedCase, parseEngagement } from '../../src/engagement/load.js'
import type { CaseState } from '../../src/engagement/store.js'
import { createTargetExtractor, type TargetExtractor } from '../../src/extract/extractor.js'
import { resolvePaths } from '../../src/paths.js'
import type { GuardContext } from '../../src/policy/guard.js'
import { createScopeEngine, type ScopeEngine } from '../../src/scope/engine.js'
import { createResolver, type LookupFn } from '../../src/scope/resolver.js'
import { compileTrustedInfra } from '../../src/scope/trusted-infra.js'
import type { GuardRequest } from '../../src/types.js'

export const FIXTURES = join(import.meta.dirname, '..', 'fixtures')
export const CWD = join(FIXTURES, 'commands', 'cwd')
export const HOME = join(FIXTURES, 'commands', 'home')
/** Wednesday 2026-10-21 10:00 in Amsterdam: inside the window, outside both blackouts. */
export const IN_WINDOW = new Date('2026-10-21T10:00:00+02:00')

const DNS: Record<string, string[]> = parseYaml(
  readFileSync(join(FIXTURES, 'commands', 'dns.yaml'), 'utf8'),
)

/** The fake DNS map (`fixtures/commands/dns.yaml`); every other name fails like ENOTFOUND. */
export const fakeLookup: LookupFn = async (host) => {
  const answers = DNS[host.toLowerCase()]
  if (answers === undefined) throw new Error(`getaddrinfo ENOTFOUND ${host}`)
  return answers.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }))
}

/** A table case (`table-case.yaml` / `table-case-exploit.yaml`), loaded as an active case. */
export function loadTableCase(which: 'default' | 'exploit' = 'default'): LoadedCase {
  const file = which === 'exploit' ? 'table-case-exploit.yaml' : 'table-case.yaml'
  const path = join(FIXTURES, 'engagements', file)
  const r = parseEngagement(readFileSync(path, 'utf8'), path, { now: IN_WINDOW })
  if (!r.ok) throw new Error(`fixture ${file} does not load: ${JSON.stringify(r.issues)}`)
  return r.case
}

/** An in-memory audit log that records every append (and can be made to fail). */
export interface MemoryAudit extends AuditLog {
  records: { rec: AuditRecordInput; sync: boolean }[]
  fail: boolean
}

export function memoryAudit(): MemoryAudit {
  const records: MemoryAudit['records'] = []
  const log: MemoryAudit = {
    records,
    fail: false,
    caseId: 'no-case',
    degraded: false,
    setCase() {},
    async append(rec, opts) {
      if (log.fail) {
        ;(log as { degraded: boolean }).degraded = true
        throw new Error('disk full')
      }
      records.push({ rec, sync: opts?.sync === true })
      return rec as never
    },
    async flush() {},
  }
  return log
}

export interface GuardHarness {
  ctx: GuardContext
  extractor: TargetExtractor
  lookups: string[]
  setState(s: CaseState): void
}

/**
 * A guard context over the table case: real extractor, real resolver on the fake DNS map, real
 * scope engine, the default trusted list, a fixed clock. `lookups` records every DNS query.
 */
export function guardHarness(
  opts: {
    state?: CaseState
    now?: Date
    shell?: 'posix' | 'powershell'
    audit?: AuditLog
    extractor?: TargetExtractor
  } = {},
): GuardHarness {
  const lookups: string[] = []
  const resolver = createResolver({
    lookup: async (host) => {
      lookups.push(host)
      return fakeLookup(host)
    },
  })
  const trusted = compileTrustedInfra()
  const extractor = opts.extractor ?? createTargetExtractor()
  let state: CaseState = opts.state ?? { status: 'active', case: loadTableCase() }
  let engine: { case: LoadedCase; engine: ScopeEngine } | undefined
  const ctx: GuardContext = {
    caseState: () => state,
    scope: () => {
      if (state.status !== 'active') return undefined
      if (engine?.case !== state.case) {
        engine = {
          case: state.case,
          engine: createScopeEngine({ case: state.case, resolver, trusted }),
        }
      }
      return engine.engine
    },
    extractor,
    trusted,
    audit: opts.audit ?? memoryAudit(),
    now: () => opts.now ?? IN_WINDOW,
    shell: opts.shell ?? 'posix',
    paths: resolvePaths({ home: HOME, env: {} }),
  }
  return {
    ctx,
    extractor,
    lookups,
    setState(s) {
      state = s
    },
  }
}

let nextId = 0

/** A permission request as core's executor builds it for a Bash call. */
export function bashRequest(command: string, over: Partial<GuardRequest> = {}): GuardRequest {
  nextId++
  return {
    toolName: 'Bash',
    input: { command },
    ruleKey: command,
    permissionClass: 'exec',
    summary: command,
    cwd: CWD,
    sessionId: 'sess-guard',
    depth: 0,
    toolUseId: `toolu_guard_${nextId}`,
    ...over,
  }
}

/** A Write/Edit request for `file` (relative to the cwd), keyed by its absolute path. */
export function fileRequest(tool: 'Write' | 'Edit', file: string): GuardRequest {
  nextId++
  const abs = join(CWD, file)
  return {
    toolName: tool,
    input:
      tool === 'Write'
        ? { file_path: abs, content: 'x' }
        : { file_path: abs, old_string: 'a', new_string: 'b' },
    ruleKey: abs,
    permissionClass: 'write',
    summary: `${tool} ${file}`,
    cwd: CWD,
    sessionId: 'sess-guard',
    depth: 0,
    toolUseId: `toolu_guard_${nextId}`,
  }
}
