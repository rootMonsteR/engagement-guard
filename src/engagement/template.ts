import type { CASE_PROFILES, CASE_TYPES } from './schema.js'

export interface ScaffoldOptions {
  type: (typeof CASE_TYPES)[number]
  profile?: (typeof CASE_PROFILES)[number]
  id?: string
  name?: string
  client?: string
  in?: string[]
  out?: string[]
  windowStart?: string
  windowEnd?: string
  timezone?: string
  authReference?: string
  authorisedBy?: string
  signedOn?: string
}

const TODO = 'TODO'
const COMMENT_COLUMN = 44

/** A supplied value as a YAML double-quoted scalar (a JSON string is one); missing → `TODO`. */
const value = (v: string | undefined): string => (v === undefined ? TODO : JSON.stringify(v))

/** `text` with a trailing comment aligned at COMMENT_COLUMN (at least one space before `#`). */
const note = (text: string, comment: string): string =>
  `${text.padEnd(COMMENT_COLUMN - 1)} # ${comment}`

function list(items: string[] | undefined, required: boolean): string {
  if (items === undefined || items.length === 0) return required ? `\n    - ${TODO}` : ' []'
  return items.map((item) => `\n    - ${JSON.stringify(item)}`).join('')
}

/**
 * A new engagement file as commented YAML. Every required value not supplied is the literal
 * `TODO`, which validation reports as PLACEHOLDER_VALUE until it is replaced.
 */
export function scaffoldEngagement(o: ScaffoldOptions): string {
  return `# Engagement (case) file. Replace every TODO, then run: engagement-guard engagement freeze
version: 1
${note(`id: ${value(o.id)}`, 'lowercase slug: a-z 0-9 . _ - (3-64 chars)')}
name: ${value(o.name)}
${note(`type: ${o.type}`, 'case kind: pentest | bug-bounty')}
${note(`profile: ${o.profile ?? 'external'}`, 'scope profile: external | web | internal | cloud')}
client: ${value(o.client)}
# Written authorisation you can produce on request: reference, signatory and signing date.
authorization:
  reference: ${value(o.authReference)}
  authorised_by: ${value(o.authorisedBy)}
${note(`  signed_on: ${value(o.signedOn)}`, 'YYYY-MM-DD')}
  # document: path/to/authorisation-letter.pdf
# Testing window: RFC 3339 date-times with an explicit offset (Z or +hh:mm) and an IANA zone.
window:
${note(`  start: ${value(o.windowStart)}`, 'e.g. 2026-10-20T08:00:00+02:00')}
  end: ${value(o.windowEnd)}
${note(`  timezone: ${value(o.timezone)}`, 'e.g. Europe/Amsterdam')}
# Scope: IPs, CIDRs, ranges, hostnames, *.wildcards (not the apex) or URLs; out always wins.
scope:
  in:${list(o.in, true)}
  out:${list(o.out, false)}
${note('  operator_infrastructure: []', 'your own callback hosts; never targets')}
  allow_private_targets: false
  require_ip_match: false
# Rules of engagement: permitted test classes, limits, blackout hours and prohibited actions.
roe:
${note('  allowed_test_classes: [recon, vuln-scan]', '+ exploitation | post-exploitation | bruteforce')}
  credentialed_testing: false
  intrusive_checks: false
${note('  dos_testing: false', 'cannot be enabled')}
  rate_limits: { rps: 10, pps: 500, nmap_max_timing: 3, max_parallel_hosts: 8 }
${note('  blackout_hours: []', 'e.g. { days: [mon], start: "12:00", end: "13:00" }')}
  prohibited_actions: []
# Where commands run: host (docker arrives in a later release).
execution: { backend: host, egress: restricted }   # recorded only: engagement-guard enforces no egress control
notifications: {}
# acknowledged_by / frozen are written by engagement-guard engagement freeze; never edit them by hand
`
}
