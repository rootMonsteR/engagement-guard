import type { CompiledList } from '../engagement/compile.js'
import type { LoadedCase } from '../engagement/load.js'
import type { CommandAnalysis, ExtractedTarget, SegmentAnalysis } from '../extract/extractor.js'
import { sweepLiterals } from '../extract/literals.js'
import type { RateFlags } from '../extract/rate.js'
import type { OpaqueKind } from '../extract/tokenizer.js'
import type { ToolCategory } from '../extract/tools-table.js'
import { isLocalTarget, type ScopeClass } from '../scope/engine.js'
import { hostMatches } from '../scope/hostname.js'
import {
  formatIp,
  formatRange,
  type IpRange,
  ipv6Embeddings,
  rangeContains,
  rangesIntersect,
} from '../scope/ip.js'
import { parseTarget, type Target } from '../scope/target.js'
import type { GuardRequest } from '../types.js'
import type { GuardTarget, Tier } from './decisions.js'

/**
 * The guard's view of a command (P1 Task 11): one unit per segment (nested analyses included) or
 * per structured network call, plus the DNS-free matching the guard does before any case is used.
 */

/** Categories trusted infrastructure may be used with (Appendix A, brief step 5). */
export const INFRA_USE: ReadonlySet<ToolCategory> = new Set([
  'fetch',
  'vcs',
  'package-manager',
  'dns',
  'http-client',
  'remote-access',
])
/** Categories that never touch trusted infrastructure as a target (INFRA_NOT_TARGET). */
export const NOT_FOR_INFRA: ReadonlySet<ToolCategory> = new Set([
  'port-scanner',
  'web-scanner',
  'fuzzer',
  'passive-recon',
  'smb-ad',
  'exploit-framework',
  'bruteforce',
  'dos',
  'listener',
])
/** Categories whose URL targets URL scope entries may authorise. */
export const HTTP_CATEGORIES: ReadonlySet<ToolCategory> = new Set([
  'http-client',
  'web-scanner',
  'fuzzer',
  'fetch',
])
/** Opaque kinds that hide which program runs at all. */
const HIDING: ReadonlySet<OpaqueKind> = new Set([
  'eval',
  'nested-command-unresolved',
  'piped-code',
  'encoded-command',
  'script-written-here',
])
/** A substitution on an interpreter segment: the code it runs is computed, whatever was analysed. */
const SUBSTITUTION: ReadonlySet<OpaqueKind> = new Set([
  'command-substitution',
  'backticks',
  'process-substitution',
])
/**
 * PowerShell pipeline stages that only display, filter or discard objects (`… | Out-Null`); they
 * are not network actions even when another stage of the pipeline is.
 */
const PS_SINKS: ReadonlySet<string> = new Set([
  'out-null',
  'out-host',
  'out-string',
  'out-default',
  'write-output',
  'write-host',
  'select-object',
  'select',
  'where-object',
  'where',
  'sort-object',
  'sort',
  'measure-object',
  'measure',
  'format-table',
  'ft',
  'format-list',
  'fl',
  'format-wide',
  'fw',
  'more',
])

/** PowerShell syntax that computes an argument: a splat word, a sub-expression, a script block, a variable or an escape. */
const PS_COMPUTED = /(?:^|\s)@|[(){}$`]/

export interface Unit {
  seg: SegmentAnalysis | null
  category: ToolCategory | null
  /** The tier before RoE escalation (structured network tools: recon). */
  baseTier: Tier | 'dos' | null
  knownNetwork: boolean
  /** Live (non-inert) targets. */
  targets: ExtractedTarget[]
  opaque: OpaqueKind[]
  excludes: IpRange[]
  rate: RateFlags
  /** The command run cannot be known (eval, a `$VAR` program, an interpreter fed opaque code). */
  hides: boolean
  /** An interpreter or unknown program given targets. */
  interpreter: boolean
  /** P15: a package manager / VCS action on its implicit default registry or remote. */
  implicit: boolean
  relevant: boolean
}

/** Opaque markers other than `powershell`, which is reported as POWERSHELL_NETWORK_TOOL. */
export const realOpaque = (u: { opaque: OpaqueKind[] }) =>
  u.opaque.filter((k) => k !== 'powershell')
export const blocking = (u: Unit) => u.hides || realOpaque(u).length > 0

function segmentUnit(seg: SegmentAnalysis, psNetwork: boolean): Unit {
  const targets = seg.targets.filter((t) => !t.inert)
  const program = seg.program ?? ''
  const ps = seg.opaque.includes('powershell')
  const nonPs = realOpaque(seg)
  // Fix round 2 (N1): PowerShell computes arguments at run time — `(gc r)`, `@args` splatting,
  // `{…}` script blocks, `$x`, backtick escapes — and the posix-style tokenizer drops the brackets,
  // so a network segment carrying any of them cannot be read: it hides its real arguments.
  const computed = ps && (seg.knownNetwork || targets.length > 0) && PS_COMPUTED.test(seg.text)
  // An interpreter fed code the extractor could not analyse (`python3 -c "$CODE"`, a here-doc). A
  // `sh -c` body that was analysed is judged by its own segments; an unbalanced quote alone is the
  // chain splitter cutting a quoted `;`, not hidden code.
  const hides =
    computed ||
    seg.opaque.some((k) => HIDING.has(k)) ||
    program.includes('$') ||
    program.includes('`') ||
    (seg.category === 'interpreter' &&
      seg.nested === null &&
      nonPs.some((k) => k !== 'unbalanced-quote')) ||
    (seg.category === 'interpreter' && nonPs.some((k) => SUBSTITUTION.has(k)))
  const interpreter =
    !ps && targets.length > 0 && (seg.category === 'interpreter' || seg.tool === null)
  // P15 (fix round 1, I1): the `powershell` marker says how the line was parsed, not that the
  // segment hides anything, so it does not cancel an implicit registry fetch. Every argument must
  // be a plain literal word (fix round 2, N1).
  const implicit =
    (seg.category === 'package-manager' || seg.category === 'vcs') &&
    seg.knownNetwork &&
    targets.length === 0 &&
    nonPs.length === 0 &&
    !hides
  const psStage = ps && psNetwork && !PS_SINKS.has(program.toLowerCase())
  return {
    seg,
    category: seg.category,
    baseTier: seg.hardDeny !== null ? 'dos' : seg.nonNetwork ? null : seg.tier,
    knownNetwork: seg.knownNetwork,
    targets,
    opaque: [...seg.opaque],
    excludes: seg.excludes,
    rate: seg.rate,
    hides,
    interpreter,
    implicit,
    relevant: seg.knownNetwork || targets.length > 0 || hides || psStage,
  }
}

/** Every segment of the analysis and of its nested analyses (`sh -c`, `eval`, `docker run` …). */
export function unitsOf(a: CommandAnalysis): Unit[] {
  const psNetwork = a.shell === 'powershell' && a.knownNetwork
  const out: Unit[] = []
  const walk = (an: CommandAnalysis) => {
    for (const seg of an.segments) {
      out.push(segmentUnit(seg, psNetwork))
      if (seg.nested) walk(seg.nested)
    }
  }
  walk(a)
  return out
}

const literalTarget = (
  raw: string,
  target: Target,
  provenance: ExtractedTarget['provenance'],
): ExtractedTarget => ({
  raw,
  target,
  provenance,
  segment: 0,
  source: null,
  inert: false,
  role: 'target',
})

/** A structured network tool (P2): declared targets, or a literal sweep of its input. */
export function networkUnit(req: GuardRequest, declared: string[] | undefined): Unit {
  const opaque: OpaqueKind[] = []
  const targets: ExtractedTarget[] = []
  if (declared !== undefined) {
    for (const raw of declared) {
      const target = parseTarget(raw)
      if (target === undefined) {
        if (!opaque.includes('unparseable-target')) opaque.push('unparseable-target')
        continue
      }
      targets.push(literalTarget(raw, target, 'flag'))
    }
  } else {
    for (const hit of sweepLiterals([JSON.stringify(req.input) ?? ''])) {
      targets.push(literalTarget(hit.raw, hit.target, 'literal'))
    }
  }
  return {
    seg: null,
    category: 'http-client',
    baseTier: 'recon',
    knownNetwork: true,
    targets: dedupe(targets),
    opaque,
    excludes: [],
    rate: { raw: [] },
    hides: false,
    interpreter: false,
    implicit: false,
    relevant: true,
  }
}

/** One entry per raw target; the `target` role wins over `infra`. */
export function dedupe(list: ExtractedTarget[]): ExtractedTarget[] {
  const byRaw = new Map<string, ExtractedTarget>()
  for (const t of list) {
    const prev = byRaw.get(t.raw)
    if (prev === undefined) byRaw.set(t.raw, t)
    else if (prev.role === 'infra' && t.role === 'target') byRaw.set(t.raw, t)
  }
  return [...byRaw.values()]
}

// ---- static (DNS-free) matching ------------------------------------------------------------------

const pointRange = (t: Target): IpRange | undefined => {
  if (t.kind === 'ip') return { family: t.ip.family, start: t.ip.value, end: t.ip.value }
  if (t.kind === 'range') return t.range
  if (t.kind === 'url' && t.ip !== undefined) {
    return { family: t.ip.family, start: t.ip.value, end: t.ip.value }
  }
  return undefined
}

const hostName = (t: Target): string | undefined =>
  t.kind === 'host' || (t.kind === 'url' && t.ip === undefined) ? t.host : undefined

const addressText = (t: Target, r: IpRange) =>
  t.kind === 'range' ? formatRange(r) : formatIp({ family: r.family, value: r.start })

/** The trusted entry naming `t` by name or address (never by DNS); `undefined` when none does. */
export function trustedRule(list: CompiledList, t: Target): string | undefined {
  const r = pointRange(t)
  if (r !== undefined) return list.ranges.find((e) => rangeContains(e.range, r))?.text
  const host = hostName(t)
  if (host === undefined) return undefined
  return (
    list.hosts.find((h) => hostMatches(h.pattern, host))?.text ??
    list.urls.find((u) => u.host === host)?.text
  )
}

/** Whether one compiled list mentions `t` statically (ranges intersect, names or URL hosts match). */
function listMentions(l: CompiledList, t: Target): boolean {
  const r = pointRange(t)
  if (r !== undefined) {
    const text = addressText(t, r)
    return (
      l.ranges.some(
        (e) =>
          rangesIntersect(e.range, r) ||
          ipv6Embeddings(e.range).some((alias) => rangesIntersect(alias, r)),
      ) || l.urls.some((u) => u.host === text)
    )
  }
  const host = hostName(t)
  if (host === undefined) return false
  return l.hosts.some((h) => hostMatches(h.pattern, host)) || l.urls.some((u) => u.host === host)
}

/** Whether the case's `in` or `out` list mentions `t` (then the case classifies it, not the exemption). */
export const caseLists = (c: LoadedCase, t: Target): boolean =>
  listMentions(c.scope.in, t) || listMentions(c.scope.out, t)

/** Ruling P12 (out first): the case's `out` list mentions `t`, loopback or not. */
export const caseOut = (c: LoadedCase, t: Target): boolean => listMentions(c.scope.out, t)

/** Targets before classification: local, trusted (by name/address) or `fallback`. */
export function staticTargets(
  units: Unit[],
  trusted: CompiledList,
  fallback: ScopeClass,
): GuardTarget[] {
  const all = dedupe(units.flatMap((u) => u.targets))
  return all.map((t) => {
    const local = isLocalTarget(t.target)
    const rule = local ? undefined : trustedRule(trusted, t.target)
    return {
      raw: t.raw,
      class: local ? 'local' : rule !== undefined ? 'trusted-infra' : fallback,
      rule: rule ?? null,
      resolved: [],
      role: t.role,
    }
  })
}

// ---- tiers and opaque unions ---------------------------------------------------------------------

const TIER_RANK: Readonly<Record<Tier | 'dos', number>> = {
  recon: 0,
  'vuln-scan': 1,
  bruteforce: 2,
  exploitation: 3,
  'post-exploitation': 4,
  dos: 5,
}

export function maxTier(tiers: (Tier | 'dos' | null)[]): Tier | 'dos' | null {
  let best: Tier | 'dos' | null = null
  for (const t of tiers) {
    if (t !== null && (best === null || TIER_RANK[t] > TIER_RANK[best])) best = t
  }
  return best
}

export function unionOpaque(units: Unit[], extra: OpaqueKind[] = []): OpaqueKind[] {
  const out: OpaqueKind[] = []
  for (const k of [...extra, ...units.flatMap((u) => u.opaque)]) if (!out.includes(k)) out.push(k)
  return out
}
