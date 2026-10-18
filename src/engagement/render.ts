import { redact } from '../audit/redact.js'
import { DEFAULT_COMMAND_HINT } from '../paths.js'
import { ENGAGEMENT_PATH } from './load.js'
import type { Engagement, ScopeEntry } from './schema.js'
import type { CaseState, TamperReason } from './store.js'

/**
 * The case as the model reads it (spec §6.2): the case state as text. The text is a pure function
 * of the state (no clock, no paths outside the workspace), so a system prompt built from it stays
 * byte-stable; every free-text value is redacted and flattened to one line, and URL scope entries
 * lose their userinfo.
 */

/**
 * The workspace-specific names the text uses (`GuardPaths`): the case file and the command that
 * attests a scope change. Defaults: `.guard/engagement.yaml`, `engagement-guard engagement edit`.
 */
export interface CaseTextHints {
  engagementPath?: string
  commandHint?: string
}

const MAX_LIST = 50
const MAX_ISSUES = 5
const MAX_VALUE = 200

/** C0/C1 controls, format characters (bidi controls, zero-width), line and paragraph separators. */
const UNSAFE_CHARS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]+/gu

/** One line of plain text, secrets redacted, cut at `max`. */
function clean(value: string, max = MAX_VALUE): string {
  const flat = redact(value).replace(UNSAFE_CHARS, ' ').replace(/\s+/g, ' ').trim()
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat
}

/** `scheme://user:pass@host/…` → `scheme://host/…`: a scope entry never shows credentials. */
const stripUserinfo = (target: string): string =>
  target.replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/?#\s]*@/i, '$1')

function entryLine(entry: ScopeEntry): string {
  const target = typeof entry === 'string' ? entry : entry.target
  const note = typeof entry === 'string' ? undefined : entry.note
  const shown = clean(stripUserinfo(target))
  return note === undefined || note.trim() === '' ? shown : `${shown} (${clean(note, 120)})`
}

/** A titled bullet list, at most 50 items, then "…and N more". */
function list(title: string, items: string[]): string[] {
  if (items.length === 0) return [`${title}: none`]
  const shown = items.slice(0, MAX_LIST).map((i) => `- ${i}`)
  const more = items.length - MAX_LIST
  return [`${title} (${items.length}):`, ...shown, ...(more > 0 ? [`- …and ${more} more`] : [])]
}

const yesNo = (b: boolean) => (b ? 'yes' : 'no')
const short = (hash: string) => hash.slice(0, 12)

/** `2026-10-20 08:00 (UTC+02:00)`: the instant on the wall clock of `timeZone`. */
function wallTime(iso: string, timeZone: string): string {
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return clean(iso)
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(d)
  const part = (type: Intl.DateTimeFormatPartTypes) =>
    Number(parts.find((p) => p.type === type)?.value)
  const [y, mo, day, h, mi] = [
    part('year'),
    part('month'),
    part('day'),
    part('hour') % 24,
    part('minute'),
  ]
  const wallMs = Date.UTC(y, mo - 1, day, h, mi)
  const instantMs = d.getTime() - d.getUTCSeconds() * 1000 - d.getUTCMilliseconds()
  const offset = Math.round((wallMs - instantMs) / 60_000)
  const sign = offset < 0 ? '-' : '+'
  const abs = Math.abs(offset)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${y}-${pad(mo)}-${pad(day)} ${pad(h)}:${pad(mi)} (UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)})`
}

function blackoutLine(e: Engagement): string {
  const b = e.roe.blackout_hours
  if (b.length === 0) return 'Blackout hours: none'
  const items = b.map(
    (x) => `${x.days === undefined ? 'daily' : x.days.join(',')} ${x.start}–${x.end}`,
  )
  return `Blackout hours (${e.window.timezone}, no network actions): ${items.join('; ')}`
}

const UPDATES =
  'If the status changes during the session, an "Engagement update" follows with a later user message and replaces this section.'

const activeEnforcement = (commandHint: string) =>
  `Enforcement: every network action is checked against this case by code (engagement-guard) and audited. When an action is denied, tell the operator why and propose \`${commandHint}\` if the client has authorised the change; never work around a denial (no other tool, encoding, proxy, script or indirection).`

const INACTIVE_ENFORCEMENT =
  'Enforcement: network actions are checked by code (engagement-guard) and audited. When an action is denied, tell the operator and propose the fix above; never work around a denial (no other tool, encoding, proxy, script or indirection).'

const DENIED =
  'Denied: every remote network action (scanners, HTTP clients, exploitation, brute force). Only loopback targets, and fetch/VCS/package/DNS use of trusted infrastructure (package registries, code hosts, resolvers), fall through to the normal permission rules.'

const TAMPER_TEXT: Readonly<Record<TamperReason, string>> = {
  'scope-changed': 'its scope changed since it was frozen',
  'attestation-removed': 'its acknowledged_by block was removed',
  unfrozen: 'its frozen block was removed without an audited edit',
  superseded: 'it is frozen at an older hash than its latest attestation',
}

function renderActive(s: Extract<CaseState, { status: 'active' }>, commandHint: string): string {
  const e = s.case.engagement
  const tz = e.window.timezone
  const r = e.roe
  const limits = r.rate_limits
  return [
    `Status: active — ${clean(e.id)} (scope_hash ${short(s.case.scopeHash)}). Network actions are allowed only against this scope, inside the window, outside blackout hours and within the RoE.`,
    `Case: ${clean(e.id)} — ${clean(e.name)}`,
    `Type: ${e.type} (profile: ${e.profile})`,
    `Client: ${clean(e.client)}`,
    `Window: ${wallTime(e.window.start, tz)} → ${wallTime(e.window.end, tz)}, ${tz}`,
    ...list('Scope in', e.scope.in.map(entryLine)),
    ...list('Scope out — always wins over in', e.scope.out.map(entryLine)),
    ...list('Operator infrastructure', e.scope.operator_infrastructure.map(entryLine)),
    `Scope options: allow_private_targets ${e.scope.allow_private_targets}, require_ip_match ${e.scope.require_ip_match}`,
    `RoE tiers: ${r.allowed_test_classes.join(', ')} (credentialed testing: ${yesNo(r.credentialed_testing)}; intrusive checks: ${yesNo(r.intrusive_checks)}; DoS testing: never)`,
    `Rate limits: rps ${limits.rps}, pps ${limits.pps}, nmap timing T${limits.nmap_max_timing} or slower, parallel hosts ${limits.max_parallel_hosts}`,
    blackoutLine(e),
    ...list(
      'Prohibited actions',
      r.prohibited_actions.map((a) => clean(a)),
    ),
    activeEnforcement(commandHint),
    UPDATES,
  ].join('\n')
}

function renderInactive(
  s: Exclude<CaseState, { status: 'active' }>,
  engagementPath: string,
  commandHint: string,
): string {
  const lines: string[] = []
  switch (s.status) {
    case 'first-run-required':
      lines.push(
        "Status: first-run-required — the operator's first-run acknowledgement is missing or out of date.",
        DENIED,
        'Fix (operator): `engagement-guard ack` (read and accept the statement), then `engagement-guard engagement load`.',
      )
      break
    case 'none':
      lines.push(
        `Status: none — no case file (${engagementPath}) is loaded.`,
        DENIED,
        'Fix (operator): `engagement-guard init`, complete the file, check it with `engagement-guard engagement validate`, then attest it with `engagement-guard engagement freeze`.',
      )
      break
    case 'invalid': {
      const errors = s.issues.filter((i) => i.severity === 'error')
      const shown = errors.slice(0, MAX_ISSUES)
      lines.push(
        `Status: invalid — ${engagementPath} failed validation (${errors.length} error${errors.length === 1 ? '' : 's'}).`,
        ...shown.map(
          (i) => `- ${clean(i.path || '(document)', 80)} ${i.code}: ${clean(i.message)}`,
        ),
        ...(errors.length > shown.length ? [`- …and ${errors.length - shown.length} more`] : []),
        DENIED,
        'Fix (operator): correct the file (`engagement-guard engagement validate` lists every error), then `engagement-guard engagement load`.',
      )
      break
    }
    case 'unacknowledged':
      lines.push(
        `Status: unacknowledged — case ${clean(s.case.engagement.id)} is loaded but its scope is not attested and frozen.`,
        DENIED,
        'Fix (operator): review the scope and attest it with `engagement-guard engagement freeze`.',
      )
      break
    case 'tampered':
      lines.push(
        `Status: tampered — case ${clean(s.case.engagement.id)}: ${TAMPER_TEXT[s.reason]} (frozen at ${short(s.frozenHash)}, now ${short(s.case.scopeHash)}).`,
        DENIED,
        `Fix (operator): review the change and attest it with \`${commandHint}\` (audited).`,
      )
      break
  }
  lines.push(INACTIVE_ENFORCEMENT, UPDATES)
  return lines.join('\n')
}

/**
 * The case state as text: deterministic for a given state and hints. `hints` names the case file
 * and the attesting command of a guard with a custom `dirName` or `commandHint`.
 */
export function renderCaseContext(s: CaseState, hints: CaseTextHints = {}): string {
  const commandHint = hints.commandHint ?? DEFAULT_COMMAND_HINT
  return s.status === 'active'
    ? renderActive(s, commandHint)
    : renderInactive(s, hints.engagementPath ?? ENGAGEMENT_PATH, commandHint)
}
