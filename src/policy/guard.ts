import { dirname, join } from 'node:path'
import { releaseHeldCall } from '../audit/subscriber.js'
import type { AuditLog, AuditRecordInput } from '../audit/writer.js'
import type { CompiledList } from '../engagement/compile.js'
import type { Engagement } from '../engagement/schema.js'
import type { CaseState } from '../engagement/store.js'
import type { ExtractedTarget, TargetExtractor } from '../extract/extractor.js'
import { checkRate, type RateField } from '../extract/rate.js'
import type { OpaqueKind } from '../extract/tokenizer.js'
import type { GuardPaths } from '../paths.js'
import {
  isLocalTarget,
  type ScopeClass,
  type ScopeEngine,
  type TargetVerdict,
} from '../scope/engine.js'
import { formatIp, formatRange } from '../scope/ip.js'
import { checkTime } from '../scope/time.js'
import type { Decision, GuardHost, GuardRequest, Middleware } from '../types.js'
import {
  askPrompt,
  formatDecision,
  type GuardAnnotation,
  type GuardTarget,
  type GuardVerdict,
  REASON_CODES,
  type ReasonCode,
  type Tier,
} from './decisions.js'
import { checkDenylist } from './denylist.js'
import {
  blocking,
  caseLists,
  caseOut,
  HTTP_CATEGORIES,
  INFRA_USE,
  maxTier,
  NOT_FOR_INFRA,
  networkUnit,
  staticTargets,
  trustedRule,
  type Unit,
  unionOpaque,
  unitsOf,
} from './guard-units.js'
import {
  type ProtectedHit,
  type ProtectedScope,
  protectedCommandHit,
  protectedFileHit,
} from './protected-paths.js'
import { ALWAYS_UNSKIPPABLE, effectiveTier, tierAllowed } from './tiers.js'

/**
 * The scope guard (spec §6.5, plan Appendix A): a `before-rules` permission middleware that turns
 * the case state, the scope engine, the target extractor, the RoE tiers and the hard denylist into
 * deny / ask / ask-unskippable / pass, and audits every decision before it returns. It fails closed:
 * any exception becomes a deny with GUARD_ERROR, a degraded audit log a deny with AUDIT_UNAVAILABLE.
 *
 * Honest gaps (spec §6.5; README "Security layer"). The guard reads command text, not behaviour:
 * variables and substitution, script-built targets, obfuscation, PowerShell syntax and tools missing
 * from `KNOWN_TOOLS` ask or deny rather than being understood. For the protected case paths (P24)
 * it does not see writes made by interpreters or unmodelled programs (`python -c "open(…,'w')"`,
 * editors, `git apply`, `git checkout <rev> -- .`), archives extracted into the working directory
 * without `-C`/`-d`, downloads that pick their own name after `cd .guard` (`curl -O`), or a
 * symlink/junction created and written through within one command (a race against the canonical
 * path check). A network-level egress control is the layer below; this package ships none.
 */

export interface GuardOutcome {
  verdict: GuardVerdict
  reason: ReasonCode
  annotation: GuardAnnotation
  /** `formatDecision(annotation)`: the deny reason the model reads. */
  message: string
  /**
   * Ruling P29: a local, non-network command with no active case. The middleware then neither
   * marks the call inspected nor audits it; core rules decide alone.
   */
  quiet?: boolean
}

export interface GuardContext {
  caseState: () => CaseState
  /** The scope engine of the active case (per process, with its resolver); `undefined` otherwise. */
  scope: () => ScopeEngine | undefined
  extractor: TargetExtractor
  /** The compiled trusted-infrastructure list (`compileTrustedInfra()`). */
  trusted: CompiledList
  audit: AuditLog
  now: () => Date
  shell: 'posix' | 'powershell'
  /**
   * The workspace paths, the home and the command hint (`resolvePaths`): the case file, snapshots
   * and audit log under the workspace, and the home's `first-run.json` and `keys/`, are protected
   * paths (ruling P24); decision messages name `paths.engagementPath` and `paths.commandHint`.
   */
  paths: GuardPaths
  /** The case store's workspace; its case paths stay protected whatever the request's cwd. */
  workspace?: string
  /** Structured network tools (P2) declare their targets here; otherwise the input is swept. */
  networkTargets?: (req: GuardRequest) => string[] | undefined
}

// ---- inspected calls ------------------------------------------------------------------------------

/** Bound on remembered call ids; the oldest are forgotten first (a session never gets near it). */
const MAX_INSPECTED = 65_536
const INSPECTED = new Set<string>()

function markInspected(toolUseId: string | undefined): void {
  if (toolUseId === undefined || toolUseId === '') return
  if (INSPECTED.has(toolUseId)) return
  INSPECTED.add(toolUseId)
  if (INSPECTED.size > MAX_INSPECTED) {
    const oldest = INSPECTED.values().next()
    if (!oldest.done) INSPECTED.delete(oldest.value)
  }
}

/** Whether the guard inspected (and audited) the call; feeds `subscribeAudit`'s `inspected`. */
export function wasInspected(toolUseId: string): boolean {
  return INSPECTED.has(toolUseId)
}

/** Installations per host (a guard installed twice stays installed until both are removed). */
const INSTALLED = new WeakMap<GuardHost, number>()

/** Installs the guard as `before-rules` middleware; the returned function removes it again. */
export function installScopeGuard(host: GuardHost, mw: Middleware): () => void {
  const off = host.use(mw, 'before-rules')
  INSTALLED.set(host, (INSTALLED.get(host) ?? 0) + 1)
  let removed = false
  return () => {
    if (removed) return
    removed = true
    off()
    const n = (INSTALLED.get(host) ?? 1) - 1
    if (n > 0) INSTALLED.set(host, n)
    else INSTALLED.delete(host)
  }
}

export function isScopeGuardInstalled(host: GuardHost): boolean {
  return (INSTALLED.get(host) ?? 0) > 0
}

// ---- outcome building -----------------------------------------------------------------------------

const CASE_STATE_REASON: Readonly<Record<Exclude<CaseState['status'], 'active'>, ReasonCode>> = {
  'first-run-required': 'FIRST_RUN_REQUIRED',
  none: 'NO_ACTIVE_CASE',
  invalid: 'CASE_INVALID',
  unacknowledged: 'NOT_ACKNOWLEDGED',
  tampered: 'SCOPE_TAMPERED',
}

const CASE_STATE_CLASS: Readonly<Record<Exclude<CaseState['status'], 'active'>, ScopeClass>> = {
  'first-run-required': 'no-engagement',
  none: 'no-engagement',
  invalid: 'no-engagement',
  unacknowledged: 'not-acknowledged',
  tampered: 'not-acknowledged',
}

const VERDICT_RANK: Readonly<Record<GuardVerdict, number>> = {
  deny: 0,
  'ask-unskippable': 1,
  ask: 2,
  pass: 3,
}

/** How restrictive a class is when one raw target was classified more than once. */
const CLASS_RANK: Readonly<Record<ScopeClass, number>> = {
  'out-of-scope': 0,
  unknown: 1,
  'no-engagement': 2,
  'not-acknowledged': 2,
  'outside-window': 2,
  blackout: 2,
  'trusted-infra': 3,
  'operator-infra': 4,
  'in-scope': 5,
  local: 6,
}

const RATE_LIMIT_KEY: Readonly<Record<RateField, keyof Engagement['roe']['rate_limits']>> = {
  nmapTiming: 'nmap_max_timing',
  pps: 'pps',
  rps: 'rps',
  threads: 'rps',
  parallelHosts: 'max_parallel_hosts',
}

interface CaseInfo {
  caseId: string | null
  casePath: string
  paths: GuardPaths
}

function caseInfo(state: CaseState, cwd: string, paths: GuardPaths): CaseInfo {
  switch (state.status) {
    case 'active':
    case 'unacknowledged':
    case 'tampered':
      return { caseId: state.case.engagement.id, casePath: state.case.path, paths }
    case 'invalid':
      return { caseId: null, casePath: state.path, paths }
    default:
      return { caseId: null, casePath: join(cwd, paths.engagementPath), paths }
  }
}

/** The workspace a case file belongs to (`<ws>/.guard/engagement.yaml` → `<ws>`). */
function workspaceOf(casePath: string, engagementPath: string): string {
  const norm = casePath.replace(/\\/g, '/').toLowerCase()
  const rel = engagementPath.replace(/\\/g, '/').toLowerCase()
  if (!norm.endsWith(`/${rel}`)) return dirname(casePath)
  let ws = casePath
  for (const _ of rel.split('/')) ws = dirname(ws)
  return ws
}

/** Fix round 1 (M3): the request cwd, the store's workspace and the loaded case's workspace. */
function protectedScope(req: GuardRequest, ctx: GuardContext, state: CaseState): ProtectedScope {
  const workspaces: string[] = []
  if (ctx.workspace !== undefined) workspaces.push(ctx.workspace)
  const rel = ctx.paths.engagementPath
  if ('case' in state) workspaces.push(workspaceOf(state.case.path, rel))
  else if (state.status === 'invalid') workspaces.push(workspaceOf(state.path, rel))
  return { cwd: req.cwd, paths: ctx.paths, workspaces }
}

interface Extras {
  targets?: GuardTarget[]
  opaque?: OpaqueKind[]
  tier?: Tier | 'dos' | null
  suggestion?: string | null
  rule?: string
  detail?: string
  denyEntry?: { id: string; description: string }
}

function outcome(
  verdict: GuardVerdict,
  reason: ReasonCode,
  info: CaseInfo,
  x: Extras = {},
): GuardOutcome {
  const annotation: GuardAnnotation = {
    verdict,
    reason,
    caseId: info.caseId,
    tier: x.tier ?? null,
    targets: x.targets ?? [],
    opaque: x.opaque ?? [],
    suggestion: x.suggestion ?? null,
    ...(x.rule !== undefined ? { rule: x.rule } : {}),
    ...(x.denyEntry !== undefined ? { denyEntry: x.denyEntry } : {}),
    ...(x.detail !== undefined ? { detail: x.detail } : {}),
  }
  return {
    verdict,
    reason,
    annotation,
    message: formatDecision(annotation, {
      casePath: info.casePath,
      engagementPath: info.paths.engagementPath,
      commandHint: info.paths.commandHint,
    }),
  }
}

// ---- the decision ---------------------------------------------------------------------------------

const FILE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit'])

/**
 * The guard's decision for one request (plan Appendix A), without auditing. `'not-inspected'`
 * for requests the guard does not look at (anything but Bash, network-class tools and Write/Edit
 * to a protected path).
 */
export async function evaluateGuard(
  req: GuardRequest,
  ctx: GuardContext,
): Promise<GuardOutcome | 'not-inspected'> {
  const bash = req.toolName === 'Bash'
  const network = !bash && req.permissionClass === 'network'
  if (!bash && !network && !FILE_TOOLS.has(req.toolName)) return 'not-inspected'
  const state = ctx.caseState()
  const info = caseInfo(state, req.cwd, ctx.paths)
  const scope = protectedScope(req, ctx, state)

  if (!bash && !network) {
    // Write/Edit (ruling P24): only a protected path is inspected.
    const input = req.input as { file_path?: unknown; notebook_path?: unknown } | null | undefined
    const file =
      typeof input?.file_path === 'string'
        ? input.file_path
        : typeof input?.notebook_path === 'string'
          ? input.notebook_path
          : req.ruleKey
    const hit = protectedFileHit(file, scope) ?? protectedFileHit(req.ruleKey, scope)
    if (hit === undefined) return 'not-inspected'
    return outcome('deny', 'PROTECTED_PATH', info, {
      rule: hit.rule,
      detail: `${req.toolName} ${hit.path}`,
    })
  }

  let units: Unit[]
  let possible: ProtectedHit | undefined
  if (bash) {
    const analysis = await ctx.extractor.analyze(req.ruleKey, { cwd: req.cwd, shell: ctx.shell })
    units = unitsOf(analysis)
    // 1. The hard denylist, for every command, network or not, in every case state.
    const entry = checkDenylist(analysis)
    if (entry !== undefined) {
      return outcome('deny', 'HARD_REFUSAL', info, {
        targets: staticTargets(units, ctx.trusted, 'unknown'),
        opaque: unionOpaque(units, analysis.opaque),
        tier: maxTier(units.map((u) => u.baseTier)),
        suggestion: entry.suggest?.(analysis) ?? null,
        denyEntry: { id: entry.id, description: entry.description },
      })
    }
    // Ruling P24: the case file, snapshots, audit log and keys are never written by the model.
    const hit = protectedCommandHit(analysis, scope)
    if (hit !== undefined && hit.possible !== true) {
      return outcome('deny', 'PROTECTED_PATH', info, {
        rule: hit.rule,
        detail: `writes ${hit.path}`,
      })
    }
    possible = hit
  } else {
    units = [networkUnit(req, ctx.networkTargets?.(req))]
  }

  const o = await decideUnits(units, state, info, ctx)
  if (possible === undefined || o.verdict !== 'pass') return o
  // Fix round 2 (M11): an archive extracted into a directory that contains a protected path may
  // replace it; its contents cannot be read from the command line, so the operator confirms.
  const a = o.annotation
  return outcome('ask', 'OPAQUE_CONSTRUCT', info, {
    targets: a.targets,
    opaque: a.opaque,
    tier: a.tier,
    rule: possible.rule,
    detail: `extracts an archive into ${possible.path}, which contains a protected path`,
  })
}

/** Steps 2–7 of Appendix A over the units of an inspected request. */
async function decideUnits(
  units: Unit[],
  state: CaseState,
  info: CaseInfo,
  ctx: GuardContext,
): Promise<GuardOutcome> {
  // 2. Not network-relevant: core rules decide (quietly without an active case, ruling P29).
  const relevant = units.filter((u) => u.relevant)
  if (relevant.length === 0) {
    const o = outcome('pass', 'NOT_NETWORK', info, { opaque: unionOpaque(units) })
    return state.status === 'active' ? o : { ...o, quiet: true }
  }

  const opaque = unionOpaque(relevant)
  const listedCase = 'case' in state ? state.case : undefined
  // Ruling P12: a target the case lists in `out` is never exempt, loopback included.
  const outListed = (t: ExtractedTarget) =>
    listedCase !== undefined && caseOut(listedCase, t.target)
  const isLocal = (t: ExtractedTarget) => isLocalTarget(t.target) && !outListed(t)

  // 3. Loopback only (§6.3): every relevant unit names targets, all of them local.
  if (relevant.every((u) => !blocking(u) && u.targets.length > 0 && u.targets.every(isLocal))) {
    return outcome('pass', 'LOCAL_TARGET', info, {
      targets: staticTargets(relevant, ctx.trusted, 'local'),
      opaque,
      tier: maxTier(relevant.map((u) => u.baseTier)),
    })
  }

  // 4. Trusted infrastructure used for fetch/vcs/package/dns/remote access: static list, no DNS,
  //    every case state, inside or outside the window.
  const trustedUse = (t: ExtractedTarget) =>
    isLocal(t) ||
    (trustedRule(ctx.trusted, t.target) !== undefined &&
      (listedCase === undefined || !caseLists(listedCase, t.target)))
  const exempt = relevant.every(
    (u) =>
      !blocking(u) &&
      u.category !== null &&
      INFRA_USE.has(u.category) &&
      (u.implicit || (u.targets.length > 0 && u.targets.every(trustedUse))),
  )
  if (exempt) {
    return outcome('pass', 'TRUSTED_INFRA', info, {
      targets: staticTargets(relevant, ctx.trusted, 'trusted-infra'),
      opaque,
      tier: maxTier(relevant.map((u) => u.baseTier)),
    })
  }

  // 5. No usable case: deny by default.
  if (state.status !== 'active') {
    return outcome('deny', CASE_STATE_REASON[state.status], info, {
      targets: staticTargets(relevant, ctx.trusted, CASE_STATE_CLASS[state.status]),
      opaque,
      tier: maxTier(relevant.map((u) => u.baseTier)),
      ...caseStateRule(state, ctx.paths),
    })
  }

  const e = state.case.engagement
  const roe = e.roe

  // 6. Window and blackout hours.
  const time = checkTime(e, ctx.now())
  if (!time.ok) {
    return outcome('deny', time.reason, info, {
      targets: staticTargets(
        relevant,
        ctx.trusted,
        time.reason === 'BLACKOUT' ? 'blackout' : 'outside-window',
      ),
      opaque,
      tier: maxTier(relevant.map((u) => tierOf(u, roe))),
      rule: time.message,
    })
  }

  // 7. Classify every target, then collect every row: deny > ask-unskippable > ask > pass.
  const engine = ctx.scope()
  if (engine === undefined) throw new Error('no scope engine for the active case')
  return decideActive(relevant, engine, roe, info, opaque)
}

function caseStateRule(
  state: Exclude<CaseState, { status: 'active' }>,
  paths: GuardPaths,
): Pick<Extras, 'rule' | 'detail'> {
  switch (state.status) {
    case 'first-run-required':
      return { rule: 'first-run acknowledgement not recorded' }
    case 'none':
      return { rule: `no case file (${paths.engagementPath})` }
    case 'invalid': {
      const errors = state.issues.filter((i) => i.severity === 'error')
      const first = errors[0] ?? state.issues[0]
      const more = errors.length > 1 ? ` (+${errors.length - 1} more)` : ''
      return {
        rule: 'case file failed validation',
        ...(first !== undefined
          ? { detail: `${first.path || '(file)'}: ${first.message}${more}` }
          : {}),
      }
    }
    case 'unacknowledged':
      return { rule: 'acknowledged_by / frozen missing (not attested)' }
    case 'tampered':
      return {
        rule: `scope ${state.reason} since it was frozen at ${state.frozenHash.slice(0, 12)}…`,
      }
  }
}

function tierOf(u: Unit, roe: Engagement['roe']): Tier | 'dos' | null {
  return u.seg === null ? u.baseTier : effectiveTier(u.seg, roe)
}

interface Row {
  verdict: GuardVerdict
  reason: ReasonCode
  rule?: string
  detail?: string
  suggestion?: string
}

async function decideActive(
  relevant: Unit[],
  engine: ScopeEngine,
  roe: Engagement['roe'],
  info: CaseInfo,
  opaque: OpaqueKind[],
): Promise<GuardOutcome> {
  const rows: Row[] = []
  const add = (row: Row) => rows.push(row)
  const cache = new Map<string, Promise<TargetVerdict>>()
  const byRaw = new Map<string, { t: ExtractedTarget; v: TargetVerdict }>()
  const classes = new Set<ScopeClass>()
  let implicit = false

  for (const u of relevant) {
    const httpTool = u.category !== null && HTTP_CATEGORIES.has(u.category)
    const excludesKey = u.excludes.map(formatRange).join(',')
    const verdicts: { t: ExtractedTarget; v: TargetVerdict }[] = []
    for (const t of u.targets) {
      const key = `${t.raw}\u0000${httpTool}\u0000${excludesKey}`
      let p = cache.get(key)
      if (p === undefined) {
        p = engine.classify(t.target, { httpTool, excludes: u.excludes })
        cache.set(key, p)
      }
      const v = await p
      verdicts.push({ t, v })
      const prev = byRaw.get(t.raw)
      if (
        prev === undefined ||
        CLASS_RANK[v.class] < CLASS_RANK[prev.v.class] ||
        (prev.t.role === 'infra' && t.role === 'target')
      ) {
        byRaw.set(t.raw, { t: prev !== undefined && prev.t.role === 'target' ? prev.t : t, v })
      }
    }
    const allLocal = u.targets.length > 0 && verdicts.every((x) => x.v.class === 'local')
    const aimed = u.targets.filter((t) => t.role === 'target').length
    if (u.implicit) implicit = true

    for (const { t, v } of verdicts) {
      if (t.role === 'infra') {
        // P16: infrastructure the tool only uses is fine when local, trusted or the operator's.
        if (v.class !== 'local' && v.class !== 'trusted-infra' && v.class !== 'operator-infra') {
          add({
            verdict: 'ask',
            reason: 'UNKNOWN_TARGET',
            detail: `infrastructure ${t.raw}: ${v.class}`,
          })
        }
        continue
      }
      classes.add(v.class)
      if (v.class === 'out-of-scope') add({ verdict: 'deny', reason: v.reason })
      else if (v.class === 'unknown') add({ verdict: 'ask', reason: v.reason })
      else if (
        v.class === 'trusted-infra' &&
        u.category !== null &&
        NOT_FOR_INFRA.has(u.category)
      ) {
        add({ verdict: 'deny', reason: 'INFRA_NOT_TARGET' })
      }
    }

    if (!allLocal) {
      const tier = tierOf(u, roe)
      if (tier !== null) {
        if (!tierAllowed(tier, roe)) {
          const escalated =
            tier !== u.baseTier && u.baseTier !== null
              ? ` (escalated from ${u.baseTier}: intrusive or credentialed)`
              : ''
          add({
            verdict: 'deny',
            reason: 'TIER_NOT_AUTHORISED',
            rule: `roe.allowed_test_classes: [${roe.allowed_test_classes.join(', ')}]`,
            detail: `needs ${tier}${escalated}`,
          })
        } else if (tier !== 'dos' && ALWAYS_UNSKIPPABLE.has(tier)) {
          add({ verdict: 'ask-unskippable', reason: 'EXPLOITATION_CONFIRM' })
        }
      }
      for (const v of checkRate(u.rate, roe.rate_limits)) {
        const field = (Object.entries(u.rate.flags ?? {}) as [RateField, string][]).find(
          ([, flag]) => flag === v.flag,
        )?.[0]
        const key = field !== undefined ? RATE_LIMIT_KEY[field] : 'rate_limits'
        add({
          verdict: 'deny',
          reason: 'RATE_EXCEEDS_ROE',
          rule: `roe.rate_limits.${key}: ${v.limit}`,
          detail: `${v.flag} ${v.value} exceeds ${v.limit}`,
          suggestion: v.suggestion,
        })
      }
    }

    // Fix round 1 (M7): only infrastructure (`curl -x proxy`) is still no target.
    if (u.knownNetwork && aimed === 0 && !u.implicit && u.opaque.length === 0 && !u.hides) {
      add({ verdict: 'ask', reason: 'NO_TARGETS_FOUND' })
    }
    if (blocking(u)) add({ verdict: 'ask', reason: 'OPAQUE_CONSTRUCT' })
    if (u.opaque.includes('powershell')) add({ verdict: 'ask', reason: 'POWERSHELL_NETWORK_TOOL' })
    if (u.interpreter && !allLocal) add({ verdict: 'ask', reason: 'INTERPRETER_TARGETS' })
  }

  const targets: GuardTarget[] = [...byRaw.values()].map(({ t, v }) => ({
    raw: t.raw,
    class: v.class,
    rule: v.rule,
    resolved: v.resolved.map(formatIp),
    role: t.role,
  }))
  const tier = maxTier(relevant.map((u) => tierOf(u, roe)))

  if (rows.length === 0) {
    const reason: ReasonCode = classes.has('in-scope')
      ? 'IN_SCOPE'
      : classes.has('operator-infra')
        ? 'OPERATOR_INFRA'
        : classes.has('trusted-infra') || implicit
          ? 'TRUSTED_INFRA'
          : classes.has('local')
            ? 'LOCAL_TARGET'
            : 'NOT_NETWORK'
    return outcome('pass', reason, info, { targets, opaque, tier })
  }
  const verdict = rows.reduce<GuardVerdict>(
    (best, r) => (VERDICT_RANK[r.verdict] < VERDICT_RANK[best] ? r.verdict : best),
    'pass',
  )
  const order = (r: ReasonCode) => REASON_CODES.indexOf(r)
  const chosen = rows
    .filter((r) => r.verdict === verdict)
    .reduce((best, r) => (order(r.reason) < order(best.reason) ? r : best))
  return outcome(verdict, chosen.reason, info, {
    targets,
    opaque,
    tier,
    suggestion: chosen.suggestion ?? null,
    ...(chosen.rule !== undefined ? { rule: chosen.rule } : {}),
    ...(chosen.detail !== undefined ? { detail: chosen.detail } : {}),
  })
}

// ---- the middleware -------------------------------------------------------------------------------

const messageOf = (err: unknown): string => (err instanceof Error ? err.message : String(err))
const nameOf = (err: unknown): string => (err instanceof Error ? err.name : typeof err)

function failClosed(
  reason: 'GUARD_ERROR' | 'AUDIT_UNAVAILABLE',
  ctx: GuardContext,
  req: GuardRequest,
  rule: string,
  detail: string,
): GuardOutcome {
  let info: CaseInfo = {
    caseId: null,
    casePath: join(req.cwd, ctx.paths.engagementPath),
    paths: ctx.paths,
  }
  try {
    info = caseInfo(ctx.caseState(), req.cwd, ctx.paths)
  } catch {
    // keep the fallback: the case store itself may be what failed
  }
  return outcome('deny', reason, info, { rule, detail })
}

const guardError = (ctx: GuardContext, req: GuardRequest, err: unknown) =>
  failClosed('GUARD_ERROR', ctx, req, `guard exception: ${nameOf(err)}`, messageOf(err))

function decisionRecord(req: GuardRequest, o: GuardOutcome): AuditRecordInput {
  const a = o.annotation
  const data: Record<string, unknown> = {
    caseId: a.caseId,
    permissionClass: req.permissionClass,
    depth: req.depth,
    tier: a.tier,
    opaque: a.opaque,
    suggestion: a.suggestion,
  }
  if (a.rule !== undefined) data.rule = a.rule
  if (a.detail !== undefined) data.detail = a.detail
  if (a.denyEntry !== undefined) data.denyEntry = a.denyEntry
  return {
    kind: 'decision',
    callId: req.toolUseId ?? null,
    tool: req.toolName,
    command: req.toolName === 'Bash' ? req.ruleKey : null,
    targets: a.targets.map((t) => ({
      raw: t.raw,
      class: t.class,
      rule: t.rule,
      resolved: t.resolved,
    })),
    scope: { verdict: a.verdict, reason: a.reason, tier: a.tier === 'dos' ? null : a.tier },
    data,
  }
}

const withGuard = (d: Decision, a: GuardAnnotation): Decision => ({
  ...d,
  annotations: { ...d.annotations, guard: a },
})

const denyOf = (o: GuardOutcome): Decision => ({
  kind: 'deny',
  reason: o.message,
  source: 'plugin',
  annotations: { guard: o.annotation },
})

/**
 * The guard as a `before-rules` middleware. Deny returns at once; ask and pass delegate to core
 * (`next()`): a core deny still wins, otherwise a guard ask is returned as an ask from the plugin
 * (unskippable for exploitation, never with an "allow always" rule), and a pass returns core's
 * decision. The call is marked inspected and its `decision` record written (fsync on deny) before
 * anything is returned or delegated, so before core emits `permission.decision` (P6). A quiet pass
 * (ruling P29) goes straight to core. Nothing thrown escapes: it becomes a deny with GUARD_ERROR.
 */
export function createScopeGuard(ctx: GuardContext): Middleware {
  const audited = async (req: GuardRequest, o: GuardOutcome): Promise<GuardOutcome> => {
    if (ctx.audit.degraded) {
      return failClosed('AUDIT_UNAVAILABLE', ctx, req, 'audit log degraded', 'audit log degraded')
    }
    if (req.toolUseId !== undefined) releaseHeldCall(ctx.audit, req.toolUseId)
    try {
      await ctx.audit.append(decisionRecord(req, o), { sync: o.verdict === 'deny' })
      return o
    } catch (err) {
      return failClosed('AUDIT_UNAVAILABLE', ctx, req, 'audit write failed', messageOf(err))
    }
  }

  return async (req, next) => {
    let first: GuardOutcome | 'not-inspected'
    try {
      first = await evaluateGuard(req, ctx)
    } catch (err) {
      first = guardError(ctx, req, err)
    }
    if (first === 'not-inspected' || first.quiet === true) {
      // Fix round 2 (M10): nothing escapes the middleware. The call was not inspected, so the
      // deny is not audited (the subscriber records nothing for it either); it fails closed.
      try {
        return await next()
      } catch (err) {
        return denyOf(guardError(ctx, req, err))
      }
    }
    markInspected(req.toolUseId)
    const o = await audited(req, first)
    if (o.verdict === 'deny') return denyOf(o)

    let d: Decision
    try {
      d = await next()
      await ctx.audit.append({
        kind: 'permission',
        callId: req.toolUseId ?? null,
        tool: req.toolName,
        permission: {
          kind: d.kind,
          source: d.source,
          reason: d.kind === 'ask' ? d.prompt.title : d.reason,
        },
      })
    } catch (err) {
      const failed = ctx.audit.degraded
        ? failClosed('AUDIT_UNAVAILABLE', ctx, req, 'audit write failed', messageOf(err))
        : guardError(ctx, req, err)
      if (!ctx.audit.degraded) {
        try {
          await ctx.audit.append(decisionRecord(req, failed), { sync: true })
        } catch {
          // the deny stands; the log is now degraded and later calls deny AUDIT_UNAVAILABLE
        }
      }
      return denyOf(failed)
    }
    if (o.verdict === 'pass' || d.kind === 'deny') return withGuard(d, o.annotation)
    return {
      kind: 'ask',
      prompt: askPrompt(o.annotation, req.summary, ctx.paths),
      unskippable: o.verdict === 'ask-unskippable',
      source: 'plugin',
      annotations: { guard: o.annotation },
    }
  }
}
