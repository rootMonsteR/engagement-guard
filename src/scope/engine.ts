import type { CompiledList, UrlEntry } from '../engagement/compile.js'
import type { LoadedCase } from '../engagement/load.js'
import type { ReasonCode } from '../policy/decisions.js'
import { hostMatches } from './hostname.js'
import {
  classesInRange,
  classifyIp,
  formatIp,
  type IpAddr,
  type IpClass,
  type IpRange,
  ipv6Embeddings,
  isPrivateLike,
  parseCidr,
  rangeContains,
  rangesIntersect,
  subtractRanges,
} from './ip.js'
import type { Resolver } from './resolver.js'
import type { Target } from './target.js'

/**
 * Scope class of one target. The engine produces the first six; the case-state and time classes
 * (`no-engagement` … `blackout`) are set by the guard, which checks them before the engine runs.
 */
export type ScopeClass =
  | 'in-scope'
  | 'out-of-scope'
  | 'local'
  | 'operator-infra'
  | 'trusted-infra'
  | 'unknown'
  | 'no-engagement'
  | 'not-acknowledged'
  | 'outside-window'
  | 'blackout'

export interface TargetVerdict {
  target: Target
  class: ScopeClass
  reason: ReasonCode
  /** The scope entry that decided the verdict (`"in[2]: 192.0.2.0/25"`), or `null`. */
  rule: string | null
  /** Addresses the hostname resolved to; `[]` for IPs, ranges and names that were not resolved. */
  resolved: IpAddr[]
  /** The in-scope name an IP target was forward-confirmed from (derived IP, §6.3), or `null`. */
  derivedVia: string | null
}

export interface ClassifyOptions {
  /** The tool speaks HTTP, so URL scope entries (scheme, port, path prefix) can authorise it. */
  httpTool: boolean
  /** The command's own `--exclude` values; subtracted from range targets before any check. */
  excludes: IpRange[]
}

export interface ScopeEngine {
  classify(t: Target, o: ClassifyOptions): Promise<TargetVerdict>
}

type Decision = Omit<TargetVerdict, 'target'>
type UrlTarget = Extract<Target, { kind: 'url' }>

const NAT64 = parseCidr('64:ff9b::/96') as IpRange
const LOCAL_CLASSES: ReadonlySet<IpClass> = new Set(['loopback', 'unspecified'])

const pointOf = (ip: IpAddr): IpRange => ({ family: ip.family, start: ip.value, end: ip.value })

function decide(
  cls: ScopeClass,
  reason: ReasonCode,
  rule: string | null,
  resolved: IpAddr[] = [],
  derivedVia: string | null = null,
): Decision {
  return { class: cls, reason, rule, resolved, derivedVia }
}

/** `r` reaches an address of `entry`, directly or through its IPv4-mapped / NAT64 IPv6 forms. */
function reaches(entry: IpRange, r: IpRange): boolean {
  return (
    rangesIntersect(entry, r) || ipv6Embeddings(entry).some((alias) => rangesIntersect(alias, r))
  )
}

/**
 * Loopback (and, per ruling P7, unspecified) addresses reach this host. A NAT64 address reaches the
 * translator instead, so an embedded 127.0.0.1 there is not local.
 */
function isLocalAddr(ip: IpAddr): boolean {
  return LOCAL_CLASSES.has(classifyIp(ip)) && !rangeContains(NAT64, pointOf(ip))
}

function isLocalRange(r: IpRange): boolean {
  const classes = classesInRange(r)
  return (
    classes.size > 0 &&
    [...classes].every((c) => LOCAL_CLASSES.has(c)) &&
    !rangesIntersect(NAT64, r)
  )
}

/** `localhost` and its subdomains (RFC 6761) always mean this host. */
const isLocalName = (host: string): boolean => host === 'localhost' || host.endsWith('.localhost')

/**
 * Whether `t` only reaches this host (loopback or unspecified addresses, `localhost` names), decided
 * from the target text alone, without DNS and without a case: what the guard needs to let loopback
 * traffic through when no case is active (Appendix A, §6.3). A case's `out` list still wins in
 * `classify`.
 */
export function isLocalTarget(t: Target): boolean {
  switch (t.kind) {
    case 'ip':
      return isLocalAddr(t.ip)
    case 'range':
      return isLocalRange(t.range)
    case 'host':
      return isLocalName(t.host)
    case 'url':
      return t.ip !== undefined ? isLocalAddr(t.ip) : isLocalName(t.host)
  }
}

/** Addresses that must not appear in a public name's resolution (internal or this host). */
function isInternalAddr(ip: IpAddr): boolean {
  const c = classifyIp(ip)
  return isPrivateLike(c) || c === 'unspecified'
}

/**
 * Internal answers a split-horizon mirror of trusted infrastructure may give (ruling P13):
 * RFC 1918, ULA and CGNAT. Loopback, link-local and unspecified answers are the rebinding/SSRF
 * shape and stay denied.
 */
const MIRROR_CLASSES: ReadonlySet<IpClass> = new Set(['private', 'cgnat'])

function urlText(u: UrlEntry): string {
  const host = u.host.includes(':') ? `[${u.host}]` : u.host
  return `${u.scheme}://${host}:${u.port}${u.pathPrefix}`
}

function urlEntryMatches(u: UrlEntry, t: UrlTarget): boolean {
  return (
    u.scheme === t.scheme &&
    u.host === t.host &&
    u.port === t.port &&
    (t.path.startsWith(u.pathPrefix) || `${t.path}/` === u.pathPrefix)
  )
}

/** A host pattern matching `host`, or a URL entry naming it (by canonical host or IP text). */
function hostHit(list: CompiledList, host: string): string | undefined {
  return (
    list.hosts.find((h) => hostMatches(h.pattern, host))?.text ??
    list.urls.find((u) => u.host === host)?.text
  )
}

/** Classifies targets against a loaded case (§6.3). PTR lookups are never made. */
export function createScopeEngine(opts: {
  case: LoadedCase
  resolver: Resolver
  trusted: CompiledList
}): ScopeEngine {
  const { engagement: e, scope } = opts.case
  const { resolver, trusted } = opts
  const internal = e.profile === 'internal'
  const privateTargetsAllowed = internal && e.scope.allow_private_targets
  const inRanges = scope.in.ranges.map((r) => r.range)

  const outRangeHit = (r: IpRange) => scope.out.ranges.find((o) => reaches(o.range, r))?.text
  const rangeHit = (list: CompiledList, ip: IpAddr) =>
    list.ranges.find((r) => rangeContains(r.range, pointOf(ip)))?.text
  const inCovers = (ip: IpAddr) => rangeHit(scope.in, ip) !== undefined
  const inNamed = (host: string) => scope.in.hosts.some((h) => hostMatches(h.pattern, host))

  /**
   * The resolver outlives engines (its cache lasts up to 10 minutes), so a derivation recorded under
   * an earlier case is only honoured when this engine's case would still derive it: the name
   * matches `in` and not `out`, and the address passes this case's resolution guard rails.
   */
  function derivationHolds(name: string, ip: IpAddr): boolean {
    if (hostHit(scope.out, name) !== undefined || !inNamed(name)) return false
    if (e.scope.require_ip_match && !inCovers(ip)) return false
    return internal || !isInternalAddr(ip) || inCovers(ip)
  }

  /** A host or IP that only `in` URL entries name: in scope only for a matching HTTP request. */
  function urlOnly(
    t: Target,
    host: string,
    o: ClassifyOptions,
    resolved: IpAddr[],
    resolveFailed: boolean,
  ): Decision | undefined {
    const entries = scope.in.urls.filter((u) => u.host === host)
    if (entries.length === 0) return undefined
    const match =
      t.kind === 'url' && o.httpTool ? entries.find((u) => urlEntryMatches(u, t)) : undefined
    if (match !== undefined) {
      if (resolveFailed) return decide('unknown', 'UNRESOLVABLE', match.text)
      // Not recorded as derived: a URL-only authorisation never widens to the host's addresses.
      return decide('in-scope', 'IN_SCOPE', match.text, resolved)
    }
    const rule = `${entries.map((u) => u.text).join('; ')} (authorised only as ${entries.map(urlText).join(', ')})`
    return decide('unknown', 'UNKNOWN_TARGET', rule, resolved)
  }

  function classifyAddress(t: Target, ip: IpAddr, o: ClassifyOptions): Decision {
    const text = formatIp(ip)
    const out = outRangeHit(pointOf(ip)) ?? scope.out.urls.find((u) => u.host === text)?.text
    if (out !== undefined) return decide('out-of-scope', 'OUT_OF_SCOPE', out)
    if (isLocalAddr(ip)) return decide('local', 'LOCAL_TARGET', null)
    const inRule = rangeHit(scope.in, ip)
    if (inRule !== undefined) return decide('in-scope', 'IN_SCOPE', inRule)
    if (privateTargetsAllowed && isPrivateLike(classifyIp(ip))) {
      return decide('in-scope', 'IN_SCOPE', 'scope.allow_private_targets')
    }
    const via = resolver.derivedFrom(ip)
    if (via !== undefined && derivationHolds(via, ip)) {
      return decide('in-scope', 'IN_SCOPE', null, [], via)
    }
    const urlDecision = urlOnly(t, text, o, [], false)
    if (urlDecision !== undefined) return urlDecision
    const operator = rangeHit(scope.operator, ip) ?? hostHit(scope.operator, text)
    if (operator !== undefined) return decide('operator-infra', 'OPERATOR_INFRA', operator)
    const trustedRule = rangeHit(trusted, ip) ?? hostHit(trusted, text)
    if (trustedRule !== undefined) return decide('trusted-infra', 'TRUSTED_INFRA', trustedRule)
    return decide('unknown', 'UNKNOWN_TARGET', null)
  }

  async function classifyHost(t: Target, host: string, o: ClassifyOptions): Promise<Decision> {
    const out = hostHit(scope.out, host)
    if (out !== undefined) return decide('out-of-scope', 'OUT_OF_SCOPE', out)
    if (isLocalName(host)) return decide('local', 'LOCAL_TARGET', null)

    // Every hostname is resolved while a case is active; the guard rails apply to every name.
    const res = await resolver.resolve(host)
    const resolved = res.ok ? res.ips : []
    for (const ip of resolved) {
      const rule = outRangeHit(pointOf(ip))
      if (rule !== undefined) return decide('out-of-scope', 'RESOLVES_OUT_OF_SCOPE', rule, resolved)
    }
    // Ruling P13: the case's own ranges cover an answer (in, or operator ranges for an operator
    // name), and a trusted name may answer with a split-horizon mirror. Names the case lists in
    // `in` get no trusted/operator relaxation.
    const caseTarget = inNamed(host) || scope.in.urls.some((u) => u.host === host)
    const operatorName = !caseTarget && hostHit(scope.operator, host) !== undefined
    const trustedName = !caseTarget && !operatorName && hostHit(trusted, host) !== undefined
    const exempt = (ip: IpAddr) =>
      inCovers(ip) ||
      (operatorName && rangeHit(scope.operator, ip) !== undefined) ||
      (trustedName && MIRROR_CLASSES.has(classifyIp(ip)))
    if (!internal && resolved.some((ip) => isInternalAddr(ip) && !exempt(ip))) {
      return decide('out-of-scope', 'RESOLVES_PRIVATE', `profile: ${e.profile}`, resolved)
    }

    const inHost = scope.in.hosts.find((h) => hostMatches(h.pattern, host))
    if (inHost !== undefined) {
      if (!res.ok) return decide('unknown', 'UNRESOLVABLE', inHost.text)
      if (e.scope.require_ip_match && !resolved.every(inCovers)) {
        return decide('unknown', 'THIRD_PARTY_HOSTING', inHost.text, resolved)
      }
      resolver.recordDerived(host, resolved)
      return decide('in-scope', 'IN_SCOPE', inHost.text, resolved)
    }
    const urlDecision = urlOnly(t, host, o, resolved, !res.ok)
    if (urlDecision !== undefined) return urlDecision

    // Operator and trusted infrastructure match by name only, never by resolved address.
    const operator = hostHit(scope.operator, host)
    if (operator !== undefined)
      return decide('operator-infra', 'OPERATOR_INFRA', operator, resolved)
    const trustedRule = hostHit(trusted, host)
    if (trustedRule !== undefined) {
      return decide('trusted-infra', 'TRUSTED_INFRA', trustedRule, resolved)
    }
    return decide('unknown', 'UNKNOWN_TARGET', null, resolved)
  }

  function classifyRange(r: IpRange, o: ClassifyOptions): Decision {
    const pieces = subtractRanges(r, o.excludes)
    for (const piece of pieces) {
      const out = outRangeHit(piece)
      if (out !== undefined) return decide('out-of-scope', 'OUT_OF_SCOPE', out)
    }
    // Excludes that remove every address leave nothing authorised to point at; ask.
    if (pieces.length === 0) return decide('unknown', 'RANGE_NOT_FULLY_AUTHORISED', null)
    if (pieces.every(isLocalRange)) return decide('local', 'LOCAL_TARGET', null)

    const rules = scope.in.ranges
      .filter((entry) => pieces.some((p) => rangesIntersect(entry.range, p)))
      .map((entry) => entry.text)
    const uncovered = pieces.flatMap((p) => subtractRanges(p, inRanges))
    if (uncovered.length === 0) return decide('in-scope', 'IN_SCOPE', rules.join('; '))
    const allPrivate = uncovered.every((p) => [...classesInRange(p)].every(isPrivateLike))
    if (privateTargetsAllowed && allPrivate) {
      return decide('in-scope', 'IN_SCOPE', [...rules, 'scope.allow_private_targets'].join('; '))
    }
    return decide(
      'unknown',
      'RANGE_NOT_FULLY_AUTHORISED',
      rules.length > 0 ? rules.join('; ') : null,
    )
  }

  return {
    async classify(t, o) {
      let d: Decision
      switch (t.kind) {
        case 'ip':
          d = classifyAddress(t, t.ip, o)
          break
        case 'range':
          d = classifyRange(t.range, o)
          break
        case 'host':
          d = await classifyHost(t, t.host, o)
          break
        case 'url':
          d = t.ip !== undefined ? classifyAddress(t, t.ip, o) : await classifyHost(t, t.host, o)
          break
      }
      return { target: t, ...d }
    },
  }
}
