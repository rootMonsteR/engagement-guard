import { describe, expect, it } from 'vitest'
import {
  BlackoutSchema,
  CASE_PROFILES,
  CASE_TYPES,
  EngagementSchema,
  RateLimitsSchema,
  RESERVED_CASE_TYPES,
  ScopeEntrySchema,
} from '../../src/engagement/schema.js'

function base(): Record<string, unknown> {
  return {
    version: 1,
    id: 'acme-ext-2026q4',
    name: 'ACME external',
    type: 'pentest',
    client: 'ACME Corp',
    authorization: { reference: 'AL-1', authorised_by: 'Dana Reyes', signed_on: '2026-10-10' },
    window: {
      start: '2026-10-20T08:00:00+02:00',
      end: '2026-10-31T18:00:00+01:00',
      timezone: 'Europe/Amsterdam',
    },
    scope: { in: ['acme.example'] },
  }
}

function withPatch(path: string[], value: unknown): Record<string, unknown> {
  const root = base()
  let node = root
  for (const key of path.slice(0, -1)) node = node[key] as Record<string, unknown>
  node[path[path.length - 1] as string] = value
  return root
}

function failPaths(input: unknown): string[] {
  const r = EngagementSchema.safeParse(input)
  if (r.success) return []
  return r.error.issues.map((i) => i.path.join('.'))
}

describe('case kinds and profiles', () => {
  it('lists the supported, reserved and profile values', () => {
    expect(CASE_TYPES).toEqual(['pentest', 'bug-bounty'])
    expect(RESERVED_CASE_TYPES).toEqual(['hardening', 'incident', 'ai-assessment'])
    expect(CASE_PROFILES).toEqual(['external', 'web', 'internal', 'cloud'])
  })

  it('accepts bug-bounty and rejects reserved kinds at the schema level', () => {
    expect(EngagementSchema.safeParse(withPatch(['type'], 'bug-bounty')).success).toBe(true)
    expect(failPaths(withPatch(['type'], 'incident'))).toEqual(['type'])
  })

  it('accepts every profile', () => {
    for (const p of CASE_PROFILES) {
      expect(EngagementSchema.parse(withPatch(['profile'], p)).profile).toBe(p)
    }
    expect(failPaths(withPatch(['profile'], 'ot'))).toEqual(['profile'])
  })
})

describe('EngagementSchema defaults', () => {
  it('fills profile, scope, roe, execution and notifications defaults', () => {
    const e = EngagementSchema.parse(base())
    expect(e.profile).toBe('external')
    expect(e.scope).toEqual({
      in: ['acme.example'],
      out: [],
      operator_infrastructure: [],
      allow_private_targets: false,
      require_ip_match: false,
    })
    expect(e.roe).toEqual({
      allowed_test_classes: ['recon', 'vuln-scan'],
      credentialed_testing: false,
      intrusive_checks: false,
      dos_testing: false,
      rate_limits: { rps: 10, pps: 500, nmap_max_timing: 3, max_parallel_hosts: 8 },
      blackout_hours: [],
      prohibited_actions: [],
    })
    expect(e.execution).toEqual({ backend: 'host', egress: 'restricted' })
    expect(e.notifications).toEqual({})
    expect(e.frozen).toBeUndefined()
    expect(e.acknowledged_by).toBeUndefined()
  })

  it('fills inner rate-limit defaults when only some are given', () => {
    const e = EngagementSchema.parse(withPatch(['roe'], { rate_limits: { rps: 50 } }))
    expect(e.roe.rate_limits).toEqual({
      rps: 50,
      pps: 500,
      nmap_max_timing: 3,
      max_parallel_hosts: 8,
    })
  })
})

describe('EngagementSchema field rules', () => {
  it('rejects unknown keys (strict objects)', () => {
    expect(failPaths({ ...base(), extra: 1 })).toEqual([''])
    expect(failPaths(withPatch(['scope', 'inn'], ['x.example']))).toEqual(['scope'])
  })

  it('requires version 1 and a slug id', () => {
    expect(failPaths(withPatch(['version'], 2))).toEqual(['version'])
    expect(failPaths(withPatch(['id'], 'ac'))).toEqual(['id'])
    expect(failPaths(withPatch(['id'], 'Acme-case'))).toEqual(['id'])
  })

  it('only accepts dos_testing: false', () => {
    expect(failPaths(withPatch(['roe'], { dos_testing: true }))).toEqual(['roe.dos_testing'])
  })

  it('requires a non-empty in list', () => {
    expect(failPaths(withPatch(['scope'], { in: [] }))).toEqual(['scope.in'])
  })

  it('checks signed_on is a real calendar date', () => {
    expect(failPaths(withPatch(['authorization', 'signed_on'], '2026-02-30'))).toEqual([
      'authorization.signed_on',
    ])
    expect(failPaths(withPatch(['authorization', 'signed_on'], '2026-10-10T00:00:00Z'))).toEqual([
      'authorization.signed_on',
    ])
    expect(failPaths(withPatch(['authorization', 'signed_on'], '2028-02-29'))).toEqual([])
  })

  it('requires an explicit offset on window date-times', () => {
    expect(failPaths(withPatch(['window', 'start'], '2026-10-20T08:00:00'))).toEqual([
      'window.start',
    ])
    expect(failPaths(withPatch(['window', 'start'], '2026-10-20T08:00:00Z'))).toEqual([])
    expect(failPaths(withPatch(['window', 'start'], '2026-10-20T08:00:00.250-05:30'))).toEqual([])
    expect(failPaths(withPatch(['window', 'end'], '2026-10-32T08:00:00Z'))).toEqual(['window.end'])
    expect(failPaths(withPatch(['window', 'end'], '2026-10-20 08:00:00Z'))).toEqual(['window.end'])
    expect(failPaths(withPatch(['window', 'end'], '2026-10-20T08:00Z'))).toEqual(['window.end'])
  })

  it('validates the IANA time zone', () => {
    expect(failPaths(withPatch(['window', 'timezone'], 'Mars/Base'))).toEqual(['window.timezone'])
    expect(failPaths(withPatch(['window', 'timezone'], '+01:00'))).toEqual(['window.timezone'])
    expect(failPaths(withPatch(['window', 'timezone'], 'America/New_York'))).toEqual([])
  })

  it('accepts acknowledged_by and frozen blocks', () => {
    const input = {
      ...base(),
      acknowledged_by: {
        operator: 'op',
        at: '2026-10-19T10:00:00Z',
        statement_version: '1',
        host_fingerprint: 'fp',
      },
      frozen: { at: '2026-10-19T10:00:00Z', by: 'op', scope_hash: 'a'.repeat(64) },
    }
    expect(EngagementSchema.safeParse(input).success).toBe(true)
    expect(
      failPaths({ ...input, frozen: { at: 'x', by: 'op', scope_hash: 'A'.repeat(64) } }),
    ).toEqual(['frozen.scope_hash'])
  })
})

describe('sub-schemas', () => {
  it('ScopeEntrySchema takes a string or { target, note }', () => {
    expect(ScopeEntrySchema.safeParse('acme.example').success).toBe(true)
    expect(ScopeEntrySchema.safeParse({ target: 'acme.example', note: 'apex' }).success).toBe(true)
    expect(ScopeEntrySchema.safeParse('').success).toBe(false)
    expect(ScopeEntrySchema.safeParse({ target: 'acme.example', extra: 1 }).success).toBe(false)
  })

  it('BlackoutSchema checks HH:MM and day names', () => {
    expect(BlackoutSchema.safeParse({ start: '23:30', end: '01:00' }).success).toBe(true)
    const weekday = { days: ['mon'], start: '12:00', end: '13:00' }
    expect(BlackoutSchema.safeParse(weekday).success).toBe(true)
    expect(BlackoutSchema.safeParse({ start: '24:00', end: '01:00' }).success).toBe(false)
    expect(BlackoutSchema.safeParse({ start: '12:00', end: '9:00' }).success).toBe(false)
    expect(BlackoutSchema.safeParse({ ...weekday, days: ['monday'] }).success).toBe(false)
  })

  it('RateLimitsSchema bounds nmap timing and requires positive integers', () => {
    expect(RateLimitsSchema.parse({})).toEqual({
      rps: 10,
      pps: 500,
      nmap_max_timing: 3,
      max_parallel_hosts: 8,
    })
    expect(RateLimitsSchema.safeParse({ nmap_max_timing: 6 }).success).toBe(false)
    expect(RateLimitsSchema.safeParse({ rps: 0 }).success).toBe(false)
    expect(RateLimitsSchema.safeParse({ rps: 1.5 }).success).toBe(false)
  })
})
