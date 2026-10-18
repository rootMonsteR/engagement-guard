import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { LineCounter, parseDocument, type YAMLError } from 'yaml'
import type { z } from 'zod'
import { canonicalJson, sha256Hex } from '../canonical.js'
import { DEFAULT_COMMAND_HINT, DEFAULT_DIR } from '../paths.js'
import { type HostPattern, hostMatches } from '../scope/hostname.js'
import {
  classesInRange,
  classifyIp,
  type IpRange,
  isPrivateLike,
  parseIp,
  rangesIntersect,
} from '../scope/ip.js'
import { DEFAULT_TRUSTED_INFRA } from '../scope/trusted-infra.js'
import { type CompiledList, type CompiledScope, compileScope, type UrlEntry } from './compile.js'
import { CASE_TYPES, type Engagement, EngagementSchema, RESERVED_CASE_TYPES } from './schema.js'

export interface ValidationIssue {
  severity: 'error' | 'warning'
  /** Dotted path into the file, `[i]` for list items (`scope.in[0]`); `''` is the whole document. */
  path: string
  code: string
  message: string
}

export interface LoadedCase {
  path: string
  engagement: Engagement
  scope: CompiledScope
  scopeHash: string
  /** Warnings only: a case with an error never loads. */
  issues: ValidationIssue[]
}

export type LoadResult =
  | { ok: true; case: LoadedCase }
  | { ok: false; path: string; reason: 'missing' | 'invalid'; issues: ValidationIssue[] }

/** The default engagement file, relative to the workspace root (`GuardPaths.engagementPath`). */
export const ENGAGEMENT_PATH = `${DEFAULT_DIR}/engagement.yaml`

/**
 * Host names of the trusted infrastructure (`DEFAULT_TRUSTED_INFRA`, the one list) for the
 * TRUSTED_INFRA_IN_SCOPE warning: address entries dropped, `*.x` reduced to `x` (the warning
 * matches a name and its subdomains), duplicates removed.
 */
export const KNOWN_TRUSTED_HOSTS: readonly string[] = Object.freeze([
  ...new Set(
    DEFAULT_TRUSTED_INFRA.filter((entry) => parseIp(entry) === undefined).map((entry) =>
      entry.startsWith('*.') ? entry.slice(2) : entry,
    ),
  ),
])

/**
 * The hash a frozen case pins: everything the guard's decisions depend on (case type, profile,
 * scope, rules of engagement, window and execution) of the zod-parsed engagement, with defaults
 * applied, so YAML layout, key order and comments never change it. Metadata (id, name, client,
 * authorization, notifications), `acknowledged_by` and `frozen` are not part of it.
 */
export function computeScopeHash(e: Engagement): string {
  return sha256Hex(canonicalJson(scopeHashInput(e)))
}

/**
 * The part of an engagement `computeScopeHash` covers. Its canonical JSON is also the content of a
 * frozen scope snapshot, so a snapshot's sha256 is the scope hash it was frozen at.
 */
export function scopeHashInput(
  e: Engagement,
): Pick<Engagement, 'type' | 'profile' | 'scope' | 'roe' | 'window' | 'execution'> {
  return {
    type: e.type,
    profile: e.profile,
    scope: e.scope,
    roe: e.roe,
    window: e.window,
    execution: e.execution,
  }
}

const error = (path: string, code: string, message: string): ValidationIssue => ({
  severity: 'error',
  path,
  code,
  message,
})

const warning = (path: string, code: string, message: string): ValidationIssue => ({
  severity: 'warning',
  path,
  code,
  message,
})

function invalid(path: string, issues: ValidationIssue[]): LoadResult {
  return { ok: false, path, reason: 'invalid', issues }
}

function formatPath(segments: readonly PropertyKey[]): string {
  let out = ''
  for (const s of segments) {
    if (typeof s === 'number') out += `[${s}]`
    else out += out === '' ? String(s) : `.${String(s)}`
  }
  return out
}

function yamlIssue(e: YAMLError, lines: LineCounter): ValidationIssue {
  const { line, col } = lines.linePos(e.pos[0])
  const message = e.message.split('\n')[0] ?? e.message
  return error('', 'YAML_SYNTAX', `line ${line}, column ${col}: ${message}`)
}

function schemaIssue(i: z.core.$ZodIssue, raw: unknown): ValidationIssue {
  const path = formatPath(i.path)
  if (path === 'roe.dos_testing') {
    return error(
      path,
      'DOS_IMMUTABLE',
      'dos_testing must be false: denial of service is never authorised',
    )
  }
  if (path === 'type') {
    const value = (raw as { type?: unknown }).type
    if ((RESERVED_CASE_TYPES as readonly unknown[]).includes(value)) {
      return error(
        path,
        'CASE_TYPE_NOT_YET_SUPPORTED',
        `case type '${String(value)}' arrives in a later release; supported: ${CASE_TYPES.join(', ')}`,
      )
    }
  }
  return error(path, 'SCHEMA', i.message)
}

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v)

/** Every string leaf equal to or starting with `TODO`, in document order. */
function findPlaceholders(value: unknown, path: PropertyKey[] = []): ValidationIssue[] {
  if (typeof value === 'string') {
    if (!value.trim().startsWith('TODO')) return []
    const p = formatPath(path)
    return [error(p, 'PLACEHOLDER_VALUE', `'${p || 'document'}' is still a placeholder (${value})`)]
  }
  if (Array.isArray(value)) return value.flatMap((v, i) => findPlaceholders(v, [...path, i]))
  if (isPlainObject(value)) {
    return Object.entries(value).flatMap(([k, v]) => findPlaceholders(v, [...path, k]))
  }
  return []
}

function semanticErrors(e: Engagement): ValidationIssue[] {
  const issues: ValidationIssue[] = []
  if (Date.parse(e.window.end) <= Date.parse(e.window.start)) {
    issues.push(
      error(
        'window.end',
        'WINDOW_INVERTED',
        `window ends (${e.window.end}) at or before it starts (${e.window.start})`,
      ),
    )
  }
  return issues
}

// --- warnings ---------------------------------------------------------------------------------

type Item = { path: string; text: string } & (
  | { kind: 'range'; range: IpRange }
  | { kind: 'host'; pattern: HostPattern }
  | { kind: 'url'; url: UrlEntry }
)

/** The entries of a compiled list in file order, each with its `scope.<list>[i]` path. */
function itemsOf(list: CompiledList): Item[] {
  const items: Item[] = [
    ...list.ranges.map((r) => ({ kind: 'range' as const, range: r.range, text: r.text })),
    ...list.hosts.map((h) => ({ kind: 'host' as const, pattern: h.pattern, text: h.text })),
    ...list.urls.map((u) => ({ kind: 'url' as const, url: u, text: u.text })),
  ].map((item) => ({ ...item, path: `scope.${item.text.slice(0, item.text.indexOf(']') + 1)}` }))
  const index = (i: Item) => Number(i.text.slice(i.text.indexOf('[') + 1, i.text.indexOf(']')))
  return items.sort((a, b) => index(a) - index(b))
}

const label = (text: string) => text.slice(text.indexOf(': ') + 2)

function pointOf(host: string): IpRange | undefined {
  const ip = parseIp(host)
  return ip === undefined ? undefined : { family: ip.family, start: ip.value, end: ip.value }
}

/** `a` is `b` or a subdomain of it. */
const underOrEqual = (a: string, b: string) => a === b || a.endsWith(`.${b}`)

function patternsOverlap(a: HostPattern, b: HostPattern): boolean {
  if (a.kind === 'exact' && b.kind === 'exact') return a.host === b.host
  if (a.kind === 'exact') return hostMatches(b, a.host)
  if (b.kind === 'exact') return hostMatches(a, b.host)
  return underOrEqual(a.suffix, b.suffix) || underOrEqual(b.suffix, a.suffix)
}

/** Static overlap of two scope entries (no DNS: a hostname never overlaps an IP range). */
function overlaps(a: Item, b: Item): boolean {
  if (a.kind === 'url' && b.kind !== 'url') return overlaps(b, a)
  if (a.kind === 'host' && b.kind === 'range') return false
  switch (a.kind) {
    case 'range': {
      if (b.kind === 'range') return rangesIntersect(a.range, b.range)
      if (b.kind === 'url') {
        const point = pointOf(b.url.host)
        return point !== undefined && rangesIntersect(a.range, point)
      }
      return false
    }
    case 'host':
      if (b.kind === 'host') return patternsOverlap(a.pattern, b.pattern)
      return b.kind === 'url' && hostMatches(a.pattern, b.url.host)
    case 'url': {
      if (b.kind !== 'url') return false
      const [x, y] = [a.url, b.url]
      return (
        x.scheme === y.scheme &&
        x.host === y.host &&
        x.port === y.port &&
        (x.pathPrefix.startsWith(y.pathPrefix) || y.pathPrefix.startsWith(x.pathPrefix))
      )
    }
  }
}

/** A range or IP-host URL containing any address `isPrivateLike` treats as internal. */
function isPrivateItem(item: Item): boolean {
  if (item.kind === 'range') return [...classesInRange(item.range)].some(isPrivateLike)
  if (item.kind !== 'url') return false
  const ip = parseIp(item.url.host)
  return ip !== undefined && isPrivateLike(classifyIp(ip))
}

function isTrustedItem(item: Item): boolean {
  if (item.kind === 'range') return false
  if (item.kind === 'url') return KNOWN_TRUSTED_HOSTS.some((t) => underOrEqual(item.url.host, t))
  const p = item.pattern
  if (p.kind === 'exact') return KNOWN_TRUSTED_HOSTS.some((t) => underOrEqual(p.host, t))
  return KNOWN_TRUSTED_HOSTS.some((t) => underOrEqual(t, p.suffix) || underOrEqual(p.suffix, t))
}

function collectWarnings(e: Engagement, scope: CompiledScope, now: Date): ValidationIssue[] {
  const issues: ValidationIssue[] = []
  const inItems = itemsOf(scope.in)

  // A warning, not an error: the case still loads, and the case store treats it as a frozen case
  // whose attestation was removed (tampered) until an audited edit re-attests it.
  if (e.frozen !== undefined && e.acknowledged_by === undefined) {
    issues.push(
      warning(
        'frozen',
        'FROZEN_WITHOUT_ACK',
        `the case is frozen but its acknowledged_by block is missing; it will not activate until ${DEFAULT_COMMAND_HINT} re-attests it`,
      ),
    )
  }

  for (const item of inItems) {
    if (item.kind !== 'host' || item.pattern.kind !== 'wildcard') continue
    const apex = item.pattern.suffix
    const covered = inItems.some(
      (other) => other.kind === 'host' && hostMatches(other.pattern, apex),
    )
    if (!covered) {
      issues.push(
        warning(
          item.path,
          'WILDCARD_EXCLUDES_APEX',
          `${label(item.text)} does not cover ${apex} itself; add ${apex} to scope.in if it is in scope`,
        ),
      )
    }
  }

  if (e.profile !== 'internal') {
    for (const item of inItems.filter(isPrivateItem)) {
      issues.push(
        warning(
          item.path,
          'PRIVATE_IN_EXTERNAL',
          `${label(item.text)} includes private or internal address space, but the profile is '${e.profile}'`,
        ),
      )
    }
  }

  for (const item of itemsOf(scope.out)) {
    if (!inItems.some((i) => overlaps(item, i))) {
      issues.push(
        warning(
          item.path,
          'OUT_NOT_IN_IN',
          `${label(item.text)} does not overlap any scope.in entry, so excluding it has no effect`,
        ),
      )
    }
  }

  if (now.getTime() >= Date.parse(e.window.end)) {
    issues.push(
      warning('window.end', 'WINDOW_ENDED', `the testing window ended at ${e.window.end}`),
    )
  }

  for (const item of inItems.filter(isTrustedItem)) {
    issues.push(
      warning(
        item.path,
        'TRUSTED_INFRA_IN_SCOPE',
        `${label(item.text)} is shared infrastructure (package registry, VCS, distribution mirror or container registry); confirm it is really a target`,
      ),
    )
  }

  if (e.execution.backend === 'docker') {
    issues.push(
      warning(
        'execution.backend',
        'DOCKER_NOT_AVAILABLE',
        'the docker execution backend is not available yet; commands run on the host',
      ),
    )
  }
  return issues
}

/**
 * Parses and validates engagement YAML. Errors (syntax, schema, placeholders, semantic and scope
 * problems) give `reason: 'invalid'`; warnings alone keep the case loadable. `now` is only used
 * for the WINDOW_ENDED warning.
 */
export function parseEngagement(text: string, path: string, opts?: { now?: Date }): LoadResult {
  const now = opts?.now ?? new Date()
  const lines = new LineCounter()
  const doc = parseDocument(text, {
    lineCounter: lines,
    prettyErrors: false,
    // yaml reports warnings through process.emitWarning; this package never writes to the terminal.
    logLevel: 'error',
  })
  if (doc.errors.length > 0)
    return invalid(
      path,
      doc.errors.map((e) => yamlIssue(e, lines)),
    )

  let raw: unknown
  try {
    raw = doc.toJS()
  } catch (err) {
    return invalid(path, [error('', 'YAML_SYNTAX', (err as Error).message)])
  }

  const placeholders = findPlaceholders(raw)
  // A placeholder usually also fails its field's schema; report it once, as the placeholder.
  const placeholderPaths = new Set(placeholders.map((i) => i.path))
  const notPlaceholder = (i: ValidationIssue) => !placeholderPaths.has(i.path)

  const parsed = EngagementSchema.safeParse(raw)
  if (!parsed.success) {
    const schemaIssues = parsed.error.issues.map((i) => schemaIssue(i, raw)).filter(notPlaceholder)
    return invalid(path, [...schemaIssues, ...placeholders])
  }

  const engagement = parsed.data
  const { scope, issues: scopeIssues } = compileScope(engagement)
  const errors = [
    ...placeholders,
    ...semanticErrors(engagement),
    ...scopeIssues.filter(notPlaceholder),
  ]
  const warnings = collectWarnings(engagement, scope, now)
  if (errors.length > 0) return invalid(path, [...errors, ...warnings])
  return {
    ok: true,
    case: { path, engagement, scope, scopeHash: computeScopeHash(engagement), issues: warnings },
  }
}

/**
 * Reads `<cwd>/<engagementPath>` (default `.guard/engagement.yaml`); a file that does not exist
 * gives `reason: 'missing'`.
 */
export async function loadEngagement(
  cwd: string,
  opts?: { now?: Date; engagementPath?: string },
): Promise<LoadResult> {
  const path = join(cwd, opts?.engagementPath ?? ENGAGEMENT_PATH)
  let text: string
  try {
    text = await readFile(path, 'utf8')
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT' || code === 'ENOTDIR')
      return { ok: false, path, reason: 'missing', issues: [] }
    throw err
  }
  return parseEngagement(text.startsWith('﻿') ? text.slice(1) : text, path, opts)
}
