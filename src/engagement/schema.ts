import { z } from 'zod'
import { TierSchema } from '../policy/decisions.js'

/** Case kinds supported in P0–P1 (spec §2a). */
export const CASE_TYPES = ['pentest', 'bug-bounty'] as const
/** Case kinds that later slices add; a file using one is rejected with CASE_TYPE_NOT_YET_SUPPORTED. */
export const RESERVED_CASE_TYPES = ['hardening', 'incident', 'ai-assessment'] as const
/** Scope profile (spec §6.2/§6.3). */
export const CASE_PROFILES = ['external', 'web', 'internal', 'cloud'] as const

const posInt = z.number().int().positive()

const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/
// RFC 3339 date-time: seconds required, optional fraction, explicit `Z` or `±hh:mm` offset.
const ISO_DATE_TIME_OFFSET =
  /^(\d{4}-\d{2}-\d{2})T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/

function isCalendarDate(text: string): boolean {
  const m = ISO_DATE.exec(text)
  if (!m) return false
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])]
  const date = new Date(Date.UTC(y, mo - 1, d))
  return date.getUTCFullYear() === y && date.getUTCMonth() === mo - 1 && date.getUTCDate() === d
}

/** `YYYY-MM-DD` naming a real calendar date. */
const IsoDate = z
  .string()
  .refine(isCalendarDate, { message: 'expected a calendar date as YYYY-MM-DD' })

/** RFC 3339 date-time with an explicit offset, so the instant never depends on the host zone. */
const IsoDateTimeWithOffset = z.string().refine(
  (s) => {
    const m = ISO_DATE_TIME_OFFSET.exec(s)
    return m !== null && isCalendarDate(m[1] ?? '')
  },
  {
    message:
      'expected an RFC 3339 date-time with an explicit offset (Z or ±hh:mm), e.g. 2026-10-20T08:00:00+02:00',
  },
)

/** The runtime's canonical spelling of an IANA zone name, or `undefined` (offsets are refused). */
function canonicalTimeZone(tz: string): string | undefined {
  if (tz === '' || /^[+-]/.test(tz)) return undefined
  try {
    return new Intl.DateTimeFormat(undefined, { timeZone: tz }).resolvedOptions().timeZone
  } catch {
    return undefined
  }
}

/**
 * An IANA time zone name known to this runtime's Intl data, normalised to its canonical spelling
 * (`europe/amsterdam` → `Europe/Amsterdam`) so the spelling never changes the scope hash.
 */
const IanaTimeZone = z.string().transform((tz, ctx) => {
  const canonical = canonicalTimeZone(tz)
  if (canonical === undefined) {
    ctx.addIssue({
      code: 'custom',
      message: 'expected an IANA time zone name, e.g. Europe/Amsterdam',
    })
    return z.NEVER
  }
  return canonical
})

const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/

/** A scope entry: an IP spec, a host pattern or a URL, optionally with a note. */
export const ScopeEntrySchema = z.union([
  z.string().min(1),
  z.strictObject({ target: z.string().min(1), note: z.string().optional() }),
])
export type ScopeEntry = z.infer<typeof ScopeEntrySchema>

/**
 * A recurring blackout period in the window's time zone; `end` before `start` crosses midnight.
 * `start === end` has no defined meaning (empty or all day), so it is refused.
 */
export const BlackoutSchema = z
  .strictObject({
    days: z.array(z.enum(['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'])).optional(),
    start: z.string().regex(HHMM, 'expected HH:MM (24-hour)'),
    end: z.string().regex(HHMM, 'expected HH:MM (24-hour)'),
  })
  .refine((b) => b.start !== b.end, { message: 'blackout start and end must differ' })

export const RateLimitsSchema = z.strictObject({
  rps: posInt.default(10),
  pps: posInt.default(500),
  nmap_max_timing: z.number().int().min(0).max(5).default(3),
  max_parallel_hosts: posInt.default(8),
})

// zod 4: `.default()` short-circuits parsing, so `.prefault({})` is what fills the inner defaults.
/** The engagement (case) file, `.guard/engagement.yaml` (spec §6.2). */
export const EngagementSchema = z.strictObject({
  version: z.literal(1),
  id: z.string().regex(/^[a-z0-9][a-z0-9._-]{2,63}$/, 'expected a lowercase slug of 3–64 chars'),
  name: z.string().min(1),
  type: z.enum(CASE_TYPES),
  profile: z.enum(CASE_PROFILES).default('external'),
  client: z.string().min(1),
  authorization: z.strictObject({
    reference: z.string().min(1),
    authorised_by: z.string().min(1),
    signed_on: IsoDate,
    document: z.string().optional(),
  }),
  window: z.strictObject({
    start: IsoDateTimeWithOffset,
    end: IsoDateTimeWithOffset,
    timezone: IanaTimeZone,
  }),
  scope: z.strictObject({
    in: z.array(ScopeEntrySchema).min(1),
    out: z.array(ScopeEntrySchema).default([]),
    operator_infrastructure: z.array(ScopeEntrySchema).default([]),
    allow_private_targets: z.boolean().default(false),
    require_ip_match: z.boolean().default(false),
  }),
  roe: z
    .strictObject({
      allowed_test_classes: z.array(TierSchema).min(1).default(['recon', 'vuln-scan']),
      credentialed_testing: z.boolean().default(false),
      intrusive_checks: z.boolean().default(false),
      dos_testing: z.literal(false).default(false),
      rate_limits: RateLimitsSchema.prefault({}),
      blackout_hours: z.array(BlackoutSchema).default([]),
      prohibited_actions: z.array(z.string()).default([]),
    })
    .prefault({}),
  execution: z
    .strictObject({
      backend: z.enum(['host', 'docker']).default('host'),
      docker_image: z.string().optional(),
      egress: z.enum(['restricted', 'open']).default('restricted'),
    })
    .prefault({}),
  notifications: z.record(z.string(), z.unknown()).default({}),
  acknowledged_by: z
    .strictObject({
      operator: z.string(),
      at: z.string(),
      statement_version: z.string(),
      host_fingerprint: z.string(),
    })
    .optional(),
  frozen: z
    .strictObject({
      at: z.string(),
      by: z.string(),
      scope_hash: z.string().regex(/^[0-9a-f]{64}$/),
    })
    .optional(),
})
export type Engagement = z.infer<typeof EngagementSchema>
