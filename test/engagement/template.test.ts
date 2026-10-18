import { describe, expect, it } from 'vitest'
import { parseDocument } from 'yaml'
import { parseEngagement } from '../../src/engagement/load.js'
import { type ScaffoldOptions, scaffoldEngagement } from '../../src/engagement/template.js'

const NOW = new Date('2026-10-25T12:00:00Z')

const FULL: ScaffoldOptions = {
  type: 'bug-bounty',
  profile: 'web',
  id: 'acme-bb-2026',
  name: 'ACME bug bounty: "web" programme #1',
  client: 'ACME Corp',
  in: ['acme.example', '*.acme.example', 'https://portal.acme.example/app/'],
  out: ['vpn.acme.example'],
  windowStart: '2026-10-20T08:00:00+02:00',
  windowEnd: '2026-10-31T18:00:00+01:00',
  timezone: 'Europe/Amsterdam',
  authReference: 'Programme policy v3',
  authorisedBy: 'Dana Reyes, CISO',
  signedOn: '2026-10-10',
}

describe('scaffoldEngagement', () => {
  it('emits YAML that parses, with TODO for every missing required value', () => {
    const text = scaffoldEngagement({ type: 'pentest' })
    expect(parseDocument(text).errors).toEqual([])
    const r = parseEngagement(text, 'engagement.yaml', { now: NOW })
    expect(r.ok).toBe(false)
    if (r.ok) throw new Error('expected invalid')
    expect(r.reason).toBe('invalid')
    const placeholders = r.issues.filter((i) => i.code === 'PLACEHOLDER_VALUE').map((i) => i.path)
    expect(placeholders).toEqual(
      expect.arrayContaining(['authorization.reference', 'client', 'window.start']),
    )
    expect(placeholders.sort()).toEqual(
      [
        'id',
        'name',
        'client',
        'authorization.reference',
        'authorization.authorised_by',
        'authorization.signed_on',
        'window.start',
        'window.end',
        'window.timezone',
        'scope.in[0]',
      ].sort(),
    )
    // Placeholders are the only errors: the schema noise at the same paths is suppressed.
    expect(r.issues.filter((i) => i.severity === 'error').map((i) => i.code)).toEqual(
      placeholders.map(() => 'PLACEHOLDER_VALUE'),
    )
  })

  it('defaults the profile to external and keeps the case type', () => {
    const doc = parseDocument(scaffoldEngagement({ type: 'pentest' })).toJS()
    expect(doc).toMatchObject({ version: 1, type: 'pentest', profile: 'external' })
    expect(doc.roe).toMatchObject({
      dos_testing: false,
      allowed_test_classes: ['recon', 'vuln-scan'],
    })
    expect(doc.execution).toMatchObject({ backend: 'host' })
    expect(
      parseDocument(scaffoldEngagement({ type: 'pentest', profile: 'internal' })).toJS(),
    ).toMatchObject({ profile: 'internal' })
  })

  it('validates ok when every value is supplied, quoting values safely', () => {
    const text = scaffoldEngagement(FULL)
    const r = parseEngagement(text, 'engagement.yaml', { now: NOW })
    expect(r.ok ? r.case.issues : r.issues).toEqual([])
    if (!r.ok) throw new Error('expected ok')
    expect(r.case.engagement).toMatchObject({
      type: 'bug-bounty',
      profile: 'web',
      id: FULL.id,
      name: FULL.name,
      client: FULL.client,
      authorization: {
        reference: FULL.authReference,
        authorised_by: FULL.authorisedBy,
        signed_on: FULL.signedOn,
      },
      window: { start: FULL.windowStart, end: FULL.windowEnd, timezone: FULL.timezone },
      scope: { in: FULL.in, out: FULL.out },
    })
  })

  it('is short, commented and has no frozen or acknowledgement block', () => {
    const text = scaffoldEngagement({ type: 'pentest' })
    const lines = text.trimEnd().split('\n')
    expect(lines.length).toBeLessThan(60)
    expect(lines.filter((l) => l.trimStart().startsWith('#')).length).toBeGreaterThanOrEqual(6)
    const doc = parseDocument(text).toJS()
    expect(doc.frozen).toBeUndefined()
    expect(doc.acknowledged_by).toBeUndefined()
    expect(text.endsWith('\n')).toBe(true)
  })

  it('treats an empty in list as missing', () => {
    const doc = parseDocument(scaffoldEngagement({ type: 'pentest', in: [] })).toJS()
    expect(doc.scope.in).toEqual(['TODO'])
  })
})
