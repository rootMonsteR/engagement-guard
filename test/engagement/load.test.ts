import { readFileSync } from 'node:fs'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml'
import {
  computeScopeHash,
  ENGAGEMENT_PATH,
  KNOWN_TRUSTED_HOSTS,
  type LoadResult,
  loadEngagement,
  parseEngagement,
  type ValidationIssue,
} from '../../src/engagement/load.js'
import { EngagementSchema } from '../../src/engagement/schema.js'
import { parseIp } from '../../src/scope/ip.js'
import { DEFAULT_TRUSTED_INFRA } from '../../src/scope/trusted-infra.js'

const FIXTURES = join(import.meta.dirname, '..', 'fixtures', 'engagements')
const fixture = (name: string) => readFileSync(join(FIXTURES, name), 'utf8')

const IN_ACME_WINDOW = new Date('2026-10-25T12:00:00Z')
const IN_MINIMAL_WINDOW = new Date('2026-11-15T12:00:00Z')

const errors = (r: LoadResult) => (r.ok ? r.case.issues : r.issues).filter(isError)
const warnings = (r: LoadResult) => (r.ok ? r.case.issues : r.issues).filter((i) => !isError(i))
const isError = (i: ValidationIssue) => i.severity === 'error'
const codes = (issues: ValidationIssue[]) => issues.map((i) => i.code)

/** minimal.yaml with `mutate` applied to its parsed form. */
function minimalVariant(mutate: (doc: Record<string, any>) => void): string {
  const doc = parseYaml(fixture('minimal.yaml')) as Record<string, any>
  mutate(doc)
  return stringifyYaml(doc)
}

function parseMinimal(mutate: (doc: Record<string, any>) => void, now = IN_MINIMAL_WINDOW) {
  return parseEngagement(minimalVariant(mutate), 'minimal.yaml', { now })
}

describe('parseEngagement: valid fixtures', () => {
  it('accepts acme-external.yaml inside the window with no issues at all', () => {
    const r = parseEngagement(fixture('acme-external.yaml'), 'acme-external.yaml', {
      now: IN_ACME_WINDOW,
    })
    expect(r.ok).toBe(true)
    if (!r.ok) throw new Error('expected ok')
    expect(r.case.issues).toEqual([])
    expect(r.case.path).toBe('acme-external.yaml')
    expect(r.case.engagement.id).toBe('acme-ext-2026q4')
    expect(r.case.engagement.type).toBe('pentest')
    expect(r.case.engagement.profile).toBe('external')
    expect(r.case.scopeHash).toMatch(/^[0-9a-f]{64}$/)
    expect(r.case.scopeHash).toBe(computeScopeHash(r.case.engagement))
    expect(r.case.scope.in.hosts).toHaveLength(2)
    expect(r.case.scope.in.ranges).toHaveLength(2)
    expect(r.case.scope.in.urls).toEqual([
      {
        scheme: 'https',
        host: 'portal.acme-partner.example',
        port: 8443,
        pathPrefix: '/app/',
        text: 'in[4]: https://portal.acme-partner.example:8443/app/',
      },
    ])
    expect(r.case.scope.out.hosts.map((h) => h.text)).toEqual([
      'out[0]: vpn.acme.example',
      'out[1]: *.corp.acme.example',
    ])
    expect(r.case.scope.operator.ranges.map((h) => h.text)).toEqual([
      'operator_infrastructure[0]: 198.51.100.10',
    ])
  })

  it('gives exactly one warning, WINDOW_ENDED, after the window', () => {
    const r = parseEngagement(fixture('acme-external.yaml'), 'acme-external.yaml', {
      now: new Date('2026-11-05T00:00:00Z'),
    })
    expect(r.ok).toBe(true)
    expect(errors(r)).toEqual([])
    expect(warnings(r)).toEqual([
      expect.objectContaining({ severity: 'warning', code: 'WINDOW_ENDED', path: 'window.end' }),
    ])
  })

  it('accepts minimal.yaml', () => {
    const r = parseEngagement(fixture('minimal.yaml'), 'minimal.yaml', { now: IN_MINIMAL_WINDOW })
    expect(r).toMatchObject({ ok: true, case: { issues: [] } })
  })

  it('defaults now to the current time', () => {
    const r = parseEngagement(fixture('minimal.yaml'), 'minimal.yaml')
    expect(r.ok).toBe(true)
  })
})

describe('parseEngagement: frozen without acknowledged_by', () => {
  // Fix round 1 (Task 12): such a case still loads, so the case store can treat it as a
  // frozen (tampered) case that only an audited engagement-guard engagement edit re-attests.
  it('loads with a FROZEN_WITHOUT_ACK warning, not an error', () => {
    const r = parseEngagement(fixture('frozen-no-ack.yaml'), 'f.yaml', { now: IN_MINIMAL_WINDOW })
    expect(r.ok).toBe(true)
    expect(errors(r)).toEqual([])
    expect(warnings(r).map((i) => `${i.code} at '${i.path}'`)).toEqual([
      "FROZEN_WITHOUT_ACK at 'frozen'",
    ])
    expect(warnings(r)[0]?.message).toMatch(/\engagement-guard engagement edit/)
  })
})

describe('parseEngagement: invalid fixtures', () => {
  const cases: [file: string, code: string, path: string][] = [
    ['invalid-dos.yaml', 'DOS_IMMUTABLE', 'roe.dos_testing'],
    ['invalid-case-type.yaml', 'CASE_TYPE_NOT_YET_SUPPORTED', 'type'],
    ['invalid-window-inverted.yaml', 'WINDOW_INVERTED', 'window.end'],
    ['invalid-unknown-key.yaml', 'SCHEMA', 'scope'],
    ['invalid-scope-entry.yaml', 'SCOPE_ENTRY_INVALID', 'scope.in[0]'],
    ['invalid-window-offset.yaml', 'SCHEMA', 'window.start'],
    ['invalid-timezone.yaml', 'SCHEMA', 'window.timezone'],
    ['invalid-placeholder.yaml', 'PLACEHOLDER_VALUE', 'client'],
    ['invalid-yaml-syntax.yaml', 'YAML_SYNTAX', ''],
  ]
  for (const [file, code, path] of cases) {
    it(`${file} → ${code} at '${path}'`, () => {
      const r = parseEngagement(fixture(file), file, { now: IN_MINIMAL_WINDOW })
      expect(r.ok).toBe(false)
      if (r.ok) throw new Error('expected invalid')
      expect(r.reason).toBe('invalid')
      expect(r.path).toBe(file)
      // One defect can yield several issues of the same code (a YAML syntax error cascades).
      const distinct = new Set(errors(r).map((i) => `${i.code} at '${i.path}'`))
      expect([...distinct]).toEqual([`${code} at '${path}'`])
    })
  }

  it('reports YAML syntax errors with line and column', () => {
    const r = parseEngagement(fixture('invalid-yaml-syntax.yaml'), 'x.yaml')
    if (r.ok) throw new Error('expected invalid')
    expect(r.issues[0]?.message).toMatch(/line \d+, column \d+/)
  })

  it('reports a YAML syntax error for multiple documents and duplicate keys', () => {
    const multi = parseEngagement(`${fixture('minimal.yaml')}---\nversion: 1\n`, 'x.yaml')
    expect(multi.ok ? [] : codes(multi.issues)).toContain('YAML_SYNTAX')
    const dup = parseEngagement(`${fixture('minimal.yaml')}client: Other\n`, 'x.yaml')
    expect(dup.ok ? [] : codes(dup.issues)).toContain('YAML_SYNTAX')
  })

  it('reports an alias bomb as YAML_SYNTAX instead of expanding it', () => {
    const ten = (ref: string) => `[${Array(10).fill(ref).join(',')}]`
    const text = `a: &a ${ten('x')}\nb: &b ${ten('*a')}\nc: &c ${ten('*b')}\nd: ${ten('*c')}\n`
    const r = parseEngagement(text, 'x.yaml')
    expect(r.ok ? [] : r.issues.map((i) => [i.code, i.path])).toEqual([['YAML_SYNTAX', '']])
  })

  it('reports SCHEMA at the root for an empty or non-mapping document', () => {
    for (const text of ['', '- a\n- b\n', 'just a string\n']) {
      const r = parseEngagement(text, 'x.yaml')
      expect(r.ok ? [] : r.issues.map((i) => [i.code, i.path])).toEqual([['SCHEMA', '']])
    }
  })

  it('rejects a blackout whose start equals its end', () => {
    const r = parseMinimal((d) => {
      d.roe = {
        blackout_hours: [
          { start: '12:00', end: '13:00' },
          { start: '02:00', end: '02:00' },
        ],
      }
    })
    expect(r.ok ? [] : r.issues.map((i) => [i.code, i.path, i.message])).toEqual([
      ['SCHEMA', 'roe.blackout_hours[1]', 'blackout start and end must differ'],
    ])
  })

  it('never writes yaml warnings to the process (complex keys)', () => {
    const emit = vi.spyOn(process, 'emitWarning').mockImplementation(() => {})
    try {
      const r = parseEngagement(
        `${fixture('minimal.yaml')}? [a, b]
: c
`,
        'x.yaml',
      )
      expect(emit).not.toHaveBeenCalled()
      expect(r.ok ? [] : r.issues.map((i) => [i.code, i.path])).toEqual([['SCHEMA', '']])
    } finally {
      emit.mockRestore()
    }
  })

  it('maps nested zod paths with dots and [i]', () => {
    const r = parseMinimal((d) => {
      d.roe = { blackout_hours: [{ start: '12:00', end: '25:00' }] }
    })
    expect(r.ok ? [] : r.issues.map((i) => [i.code, i.path])).toEqual([
      ['SCHEMA', 'roe.blackout_hours[0].end'],
    ])
  })

  it('treats a window of zero length as inverted', () => {
    const r = parseMinimal((d) => {
      d.window.end = d.window.start
    })
    expect(codes(errors(r))).toEqual(['WINDOW_INVERTED'])
  })

  it('compares window instants, not strings', () => {
    // 10:00+02:00 is 08:00Z, which is before 09:00Z.
    const r = parseMinimal((d) => {
      d.window.start = '2026-10-20T09:00:00Z'
      d.window.end = '2026-10-20T10:00:00+02:00'
    })
    expect(codes(errors(r))).toEqual(['WINDOW_INVERTED'])
  })

  it('flags every TODO placeholder leaf and suppresses the schema noise at the same path', () => {
    const r = parseMinimal((d) => {
      d.window.start = 'TODO'
      d.authorization.signed_on = 'TODO'
      d.scope.in = ['TODO']
      d.roe = { prohibited_actions: ['TODO: list them'] }
    })
    expect(errors(r).map((i) => [i.code, i.path])).toEqual([
      ['PLACEHOLDER_VALUE', 'authorization.signed_on'],
      ['PLACEHOLDER_VALUE', 'window.start'],
      ['PLACEHOLDER_VALUE', 'scope.in[0]'],
      ['PLACEHOLDER_VALUE', 'roe.prohibited_actions[0]'],
    ])
  })

  it('flags a TODO placeholder hidden behind whitespace', () => {
    const r = parseEngagement(
      fixture('minimal.yaml').replace('client: Example Client', 'client: "  TODO"'),
      'x.yaml',
      { now: IN_MINIMAL_WINDOW },
    )
    expect(r.ok ? [] : r.issues.map((i) => [i.code, i.path])).toEqual([
      ['PLACEHOLDER_VALUE', 'client'],
    ])
  })

  it('does not flag strings that merely contain TODO', () => {
    const r = parseMinimal((d) => {
      d.name = 'Case for MASTODON todo list'
    })
    expect(r.ok).toBe(true)
  })

  it('reports placeholders alongside semantic errors when the schema passes', () => {
    const r = parseMinimal((d) => {
      d.client = 'TODO'
      d.scope.in = ['300.1.1.1']
    })
    expect(errors(r).map((i) => [i.code, i.path])).toEqual([
      ['PLACEHOLDER_VALUE', 'client'],
      ['SCOPE_ENTRY_INVALID', 'scope.in[0]'],
    ])
  })

  it('re-codes any dos_testing failure as DOS_IMMUTABLE', () => {
    const r = parseMinimal((d) => {
      d.roe = { dos_testing: 'yes' }
    })
    expect(codes(errors(r))).toEqual(['DOS_IMMUTABLE'])
  })

  it('keeps SCHEMA for type values that are neither supported nor reserved', () => {
    const r = parseMinimal((d) => {
      d.type = 'red-team'
    })
    expect(errors(r).map((i) => [i.code, i.path])).toEqual([['SCHEMA', 'type']])
  })

  it('accepts frozen together with acknowledged_by', () => {
    const r = parseMinimal((d) => {
      d.acknowledged_by = {
        operator: 'op',
        at: '2026-10-02T09:00:00Z',
        statement_version: '1',
        host_fingerprint: 'fp',
      }
      d.frozen = { at: '2026-10-02T09:00:00Z', by: 'op', scope_hash: 'a'.repeat(64) }
    })
    expect(r.ok).toBe(true)
  })

  it('still reports warnings when errors make the file invalid', () => {
    const r = parseMinimal((d) => {
      d.client = 'TODO'
      d.execution = { backend: 'docker' }
    })
    expect(r.ok).toBe(false)
    expect(codes(warnings(r))).toEqual(['DOCKER_NOT_AVAILABLE'])
  })
})

describe('parseEngagement: warnings', () => {
  it('WILDCARD_EXCLUDES_APEX when *.x is in scope without x', () => {
    const r = parseMinimal((d) => {
      d.scope.in = ['*.acme.example']
    })
    expect(r.ok).toBe(true)
    expect(warnings(r).map((i) => [i.code, i.path])).toEqual([
      ['WILDCARD_EXCLUDES_APEX', 'scope.in[0]'],
    ])
    const covered = parseMinimal((d) => {
      d.scope.in = ['*.acme.example', '*.example']
    })
    expect(codes(warnings(covered))).toEqual(['WILDCARD_EXCLUDES_APEX'])
    expect(warnings(covered)[0]?.path).toBe('scope.in[1]')
  })

  it('PRIVATE_IN_EXTERNAL unless the profile is internal', () => {
    const priv = (profile?: string) =>
      parseMinimal((d) => {
        d.scope.in = ['10.0.0.0/24', 'fd00::1', '192.0.2.0/24', 'http://172.16.0.5/']
        if (profile) d.profile = profile
      })
    expect(warnings(priv()).map((i) => [i.code, i.path])).toEqual([
      ['PRIVATE_IN_EXTERNAL', 'scope.in[0]'],
      ['PRIVATE_IN_EXTERNAL', 'scope.in[1]'],
      ['PRIVATE_IN_EXTERNAL', 'scope.in[3]'],
    ])
    expect(codes(warnings(priv('web')))).toHaveLength(3)
    expect(codes(warnings(priv('cloud')))).toHaveLength(3)
    expect(warnings(priv('internal'))).toEqual([])
  })

  it('PRIVATE_IN_EXTERNAL for a broad range that merely contains private space', () => {
    const r = parseMinimal((d) => {
      d.scope.in = ['0.0.0.0/0']
    })
    expect(codes(warnings(r))).toEqual(['PRIVATE_IN_EXTERNAL'])
  })

  it('OUT_NOT_IN_IN for an out entry that intersects nothing in in', () => {
    const r = parseMinimal((d) => {
      d.scope.in = [
        '192.0.2.0/25',
        'acme.example',
        '*.acme.example',
        'https://portal.acme.example/app/',
      ]
      d.scope.out = [
        '192.0.2.66', // inside the /25
        '192.0.2.200', // outside the /25
        'vpn.acme.example', // matched by the wildcard
        'other.example', // matches nothing
        '*.corp.acme.example', // narrower wildcard
        '*.example', // broader wildcard that covers acme.example
        'https://portal.acme.example/app/admin/', // under the in URL
        'https://shop.other.example/', // nothing
        { target: '203.0.113.0/24', note: 'never in' },
      ]
    })
    expect(r.ok).toBe(true)
    expect(warnings(r).map((i) => [i.code, i.path])).toEqual([
      ['OUT_NOT_IN_IN', 'scope.out[1]'],
      ['OUT_NOT_IN_IN', 'scope.out[3]'],
      ['OUT_NOT_IN_IN', 'scope.out[7]'],
      ['OUT_NOT_IN_IN', 'scope.out[8]'],
    ])
  })

  it('OUT_NOT_IN_IN treats a URL host and an IP URL as intersecting host and range entries', () => {
    const r = parseMinimal((d) => {
      d.scope.in = ['app.acme.example', '192.0.2.0/24', 'https://api.acme.example/v1/']
      d.scope.out = [
        'https://app.acme.example/admin/',
        'http://192.0.2.9/',
        'api.acme.example',
        'https://api.acme.example:8443/v1/',
        'https://api.acme.example/v2/',
      ]
    })
    expect(warnings(r).map((i) => i.path)).toEqual(['scope.out[3]', 'scope.out[4]'])
  })

  it('derives KNOWN_TRUSTED_HOSTS from DEFAULT_TRUSTED_INFRA (one list)', () => {
    const names = DEFAULT_TRUSTED_INFRA.filter((e) => parseIp(e) === undefined).map((e) =>
      e.startsWith('*.') ? e.slice(2) : e,
    )
    expect([...KNOWN_TRUSTED_HOSTS]).toEqual([...new Set(names)])
    for (const h of ['gitlab.com', 'bitbucket.org', 'rubygems.org', 'repo.maven.apache.org']) {
      expect(KNOWN_TRUSTED_HOSTS).toContain(h)
    }
    expect(KNOWN_TRUSTED_HOSTS).toContain('githubusercontent.com')
  })

  it('TRUSTED_INFRA_IN_SCOPE when a package registry or VCS host is a target', () => {
    const trusted = KNOWN_TRUSTED_HOSTS[0] as string
    expect(KNOWN_TRUSTED_HOSTS.length).toBeGreaterThanOrEqual(8)
    const r = parseMinimal((d) => {
      d.scope.in = ['192.0.2.10', trusted, `api.${trusted}`, `https://${trusted}/org/`]
    })
    expect(warnings(r).map((i) => [i.code, i.path])).toEqual([
      ['TRUSTED_INFRA_IN_SCOPE', 'scope.in[1]'],
      ['TRUSTED_INFRA_IN_SCOPE', 'scope.in[2]'],
      ['TRUSTED_INFRA_IN_SCOPE', 'scope.in[3]'],
    ])
    const wildcard = parseMinimal((d) => {
      d.scope.in = [`*.${trusted.split('.').slice(-1)[0]}`]
    })
    expect(codes(warnings(wildcard))).toContain('TRUSTED_INFRA_IN_SCOPE')
  })

  it('DOCKER_NOT_AVAILABLE for the docker backend', () => {
    const r = parseMinimal((d) => {
      d.execution = { backend: 'docker', docker_image: 'example/tools:1' }
    })
    expect(r.ok).toBe(true)
    expect(warnings(r).map((i) => [i.code, i.path])).toEqual([
      ['DOCKER_NOT_AVAILABLE', 'execution.backend'],
    ])
  })
})

describe('computeScopeHash', () => {
  const acme = () => {
    const r = parseEngagement(fixture('acme-external.yaml'), 'a.yaml', { now: IN_ACME_WINDOW })
    if (!r.ok) throw new Error('acme fixture must be valid')
    return r.case
  }

  it('ignores key order, comments and whitespace', () => {
    const reorder = (v: unknown): unknown => {
      if (Array.isArray(v)) return v.map(reorder)
      if (v !== null && typeof v === 'object') {
        return Object.fromEntries(
          Object.entries(v as Record<string, unknown>)
            .reverse()
            .map(([k, x]) => [k, reorder(x)]),
        )
      }
      return v
    }
    const doc = reorder(parseYaml(fixture('acme-external.yaml')))
    const text = `# reordered copy\n\n${stringifyYaml(doc, { indent: 4 })}\n# trailing comment\n`
    expect(text).not.toBe(fixture('acme-external.yaml'))
    const r = parseEngagement(text, 'b.yaml', { now: IN_ACME_WINDOW })
    if (!r.ok) throw new Error('reordered fixture must be valid')
    expect(r.case.scopeHash).toBe(acme().scopeHash)
  })

  it('ignores defaults written out explicitly', () => {
    const implicit = parseEngagement(fixture('minimal.yaml'), 'm.yaml', { now: IN_MINIMAL_WINDOW })
    const explicit = parseMinimal((d) => {
      d.scope.out = []
      d.roe = { dos_testing: false, rate_limits: { rps: 10 } }
    })
    if (!implicit.ok || !explicit.ok) throw new Error('expected ok')
    expect(explicit.case.scopeHash).toBe(implicit.case.scopeHash)
  })

  it('changes when one in entry changes', () => {
    const changed = fixture('acme-external.yaml').replace('192.0.2.0/25', '192.0.2.0/24')
    const r = parseEngagement(changed, 'c.yaml', { now: IN_ACME_WINDOW })
    if (!r.ok) throw new Error('expected ok')
    expect(r.case.scopeHash).not.toBe(acme().scopeHash)
  })

  it('changes with type, profile, scope, roe, window and execution', () => {
    const e = acme().engagement
    const h = computeScopeHash(e)
    expect(computeScopeHash({ ...e, type: 'bug-bounty' })).not.toBe(h)
    expect(computeScopeHash({ ...e, profile: 'internal' })).not.toBe(h)
    expect(computeScopeHash({ ...e, scope: { ...e.scope, require_ip_match: false } })).not.toBe(h)
    expect(computeScopeHash({ ...e, roe: { ...e.roe, intrusive_checks: true } })).not.toBe(h)
    expect(computeScopeHash({ ...e, window: { ...e.window, timezone: 'UTC' } })).not.toBe(h)
    expect(computeScopeHash({ ...e, execution: { ...e.execution, egress: 'open' } })).not.toBe(h)
    expect(computeScopeHash({ ...e, execution: { ...e.execution, backend: 'docker' } })).not.toBe(h)
  })

  it('changes when profile or egress changes in the YAML', () => {
    const base = fixture('acme-external.yaml')
    const hashOf = (text: string) => {
      const r = parseEngagement(text, 'p.yaml', { now: IN_ACME_WINDOW })
      if (!r.ok) throw new Error(`expected ok: ${JSON.stringify(r.issues)}`)
      return r.case.scopeHash
    }
    const h = hashOf(base)
    expect(hashOf(base.replace('profile: external ', 'profile: web      '))).not.toBe(h)
    expect(hashOf(base.replace('{ backend: host }', '{ backend: host, egress: open }'))).not.toBe(h)
    // egress: restricted is the default, so writing it out changes nothing.
    expect(hashOf(base.replace('{ backend: host }', '{ backend: host, egress: restricted }'))).toBe(
      h,
    )
  })

  it('treats time zone spellings as the same zone', () => {
    const parsed = (tz: string) =>
      parseMinimal((d) => {
        d.window.timezone = tz
      })
    for (const [variant, canonical] of [
      ['utc', 'UTC'],
      ['europe/amsterdam', 'Europe/Amsterdam'],
    ] as const) {
      const a = parsed(variant)
      const b = parsed(canonical)
      if (!a.ok || !b.ok) throw new Error('expected ok')
      expect(a.case.engagement.window.timezone).toBe(canonical)
      expect(a.case.scopeHash).toBe(b.case.scopeHash)
    }
  })

  it('ignores frozen, acknowledged_by and metadata', () => {
    const e = acme().engagement
    const h = computeScopeHash(e)
    expect(
      computeScopeHash({
        ...e,
        name: 'renamed',
        client: 'Other',
        notifications: { slack: '#x' },
        frozen: { at: 'x', by: 'y', scope_hash: 'a'.repeat(64) },
        acknowledged_by: { operator: 'o', at: 'x', statement_version: '1', host_fingerprint: 'f' },
      }),
    ).toBe(h)
  })

  it('is computed over the zod-parsed value', () => {
    const raw = parseYaml(fixture('minimal.yaml'))
    const r = parseEngagement(fixture('minimal.yaml'), 'm.yaml', { now: IN_MINIMAL_WINDOW })
    if (!r.ok) throw new Error('expected ok')
    expect(computeScopeHash(EngagementSchema.parse(raw))).toBe(r.case.scopeHash)
  })
})

describe('loadEngagement', () => {
  let dir: string

  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'guard-engagement-'))
    vi.stubEnv('GUARD_HOME', join(dir, 'home'))
  })

  afterEach(async () => {
    vi.unstubAllEnvs()
    await rm(dir, { recursive: true, force: true })
  })

  it('uses .guard/engagement.yaml', () => {
    expect(ENGAGEMENT_PATH).toBe('.guard/engagement.yaml')
  })

  it('reads the engagement path it is given', async () => {
    const r = await loadEngagement(dir, { engagementPath: '.case/engagement.yaml' })
    expect(r).toMatchObject({ ok: false, path: join(dir, '.case', 'engagement.yaml') })
  })

  it('reports a missing file', async () => {
    const r = await loadEngagement(dir)
    expect(r).toEqual({
      ok: false,
      path: join(dir, ENGAGEMENT_PATH),
      reason: 'missing',
      issues: [],
    })
  })

  it('loads and validates the file under cwd', async () => {
    await mkdir(join(dir, '.guard'))
    await writeFile(join(dir, ENGAGEMENT_PATH), `﻿${fixture('acme-external.yaml')}`)
    const r = await loadEngagement(dir, { now: IN_ACME_WINDOW })
    expect(r.ok).toBe(true)
    if (!r.ok) throw new Error('expected ok')
    expect(r.case.path).toBe(join(dir, ENGAGEMENT_PATH))
    expect(r.case.issues).toEqual([])
  })

  it('reports an invalid file with reason invalid', async () => {
    await mkdir(join(dir, '.guard'))
    await writeFile(join(dir, ENGAGEMENT_PATH), fixture('invalid-dos.yaml'))
    const r = await loadEngagement(dir)
    expect(r).toMatchObject({ ok: false, reason: 'invalid', path: join(dir, ENGAGEMENT_PATH) })
  })

  it('rethrows read errors other than a missing file', async () => {
    await mkdir(join(dir, ENGAGEMENT_PATH), { recursive: true })
    await expect(loadEngagement(dir)).rejects.toThrow()
  })
})
