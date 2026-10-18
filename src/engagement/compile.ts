import { type HostPattern, parseHostPattern } from '../scope/hostname.js'
import { type IpRange, parseIpSpec } from '../scope/ip.js'
import { parseTarget } from '../scope/target.js'
import type { ValidationIssue } from './load.js'
import type { Engagement, ScopeEntry } from './schema.js'

/** A URL scope entry: matches requests to this scheme/host/port whose path starts with `pathPrefix`. */
export interface UrlEntry {
  scheme: string
  host: string
  port: number
  /** URL path, always ending in `/`. */
  pathPrefix: string
  text: string
}

export interface CompiledList {
  ranges: { range: IpRange; text: string }[]
  hosts: { pattern: HostPattern; text: string }[]
  urls: UrlEntry[]
}

/** Compiled scope lists. Every `text` is `"<list>[<i>]: <entry>"`, e.g. `"in[3]: 192.0.2.0/25"`. */
export interface CompiledScope {
  in: CompiledList
  out: CompiledList
  operator: CompiledList
}

type CompiledEntry =
  | { kind: 'range'; range: IpRange }
  | { kind: 'host'; pattern: HostPattern }
  | { kind: 'url'; url: Omit<UrlEntry, 'text'> }

/** The target text of an entry (`"x"` or `{ target: "x" }`). */
export function entryTarget(entry: ScopeEntry): string {
  return typeof entry === 'string' ? entry : entry.target
}

/**
 * One scope entry: an IP spec (address, CIDR or range), a host pattern (`host` or `*.suffix`) or a
 * URL with an explicit scheme that has a default port. Ports on bare hosts, scheme-less paths and
 * URLs carrying credentials are refused: a scope entry must say exactly what it covers.
 */
function compileEntry(raw: string): CompiledEntry | undefined {
  const s = raw.trim()
  const range = parseIpSpec(s)
  if (range) return { kind: 'range', range }
  const pattern = parseHostPattern(s)
  if (pattern) return { kind: 'host', pattern }
  if (!s.includes('://')) return undefined
  const t = parseTarget(s)
  if (t?.kind !== 'url' || t.hadCredentials) return undefined
  const pathPrefix = t.path.endsWith('/') ? t.path : `${t.path}/`
  return { kind: 'url', url: { scheme: t.scheme, host: t.host, port: t.port, pathPrefix } }
}

/**
 * Compiles one list of entries. Rule texts are `"<name>[<i>]: <entry>"` and issue paths
 * `scope.<name>[<i>]`; entries that do not parse are skipped and reported in `issues`.
 */
export function compileList(
  name: string,
  entries: readonly ScopeEntry[],
  issues: ValidationIssue[],
): CompiledList {
  const list: CompiledList = { ranges: [], hosts: [], urls: [] }
  entries.forEach((entry, i) => {
    const target = entryTarget(entry)
    const text = `${name}[${i}]: ${target}`
    const compiled = compileEntry(target)
    if (compiled === undefined) {
      issues.push({
        severity: 'error',
        path: `scope.${name}[${i}]`,
        code: 'SCOPE_ENTRY_INVALID',
        message: `'${target}' is not an IP address, CIDR, IP range, hostname, *.wildcard or URL`,
      })
      return
    }
    switch (compiled.kind) {
      case 'range':
        list.ranges.push({ range: compiled.range, text })
        break
      case 'host':
        list.hosts.push({ pattern: compiled.pattern, text })
        break
      case 'url':
        list.urls.push({ ...compiled.url, text })
        break
    }
  })
  return list
}

/** Compiles the three scope lists; entries that do not parse become SCOPE_ENTRY_INVALID errors. */
export function compileScope(e: Engagement): { scope: CompiledScope; issues: ValidationIssue[] } {
  const issues: ValidationIssue[] = []
  const scope: CompiledScope = {
    in: compileList('in', e.scope.in, issues),
    out: compileList('out', e.scope.out, issues),
    operator: compileList('operator_infrastructure', e.scope.operator_infrastructure, issues),
  }
  return { scope, issues }
}
