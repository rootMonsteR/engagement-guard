import { describe, expect, it } from 'vitest'
import { compileScope } from '../../src/engagement/compile.js'
import { type Engagement, EngagementSchema } from '../../src/engagement/schema.js'
import { parseCidr } from '../../src/scope/ip.js'

function engagement(scope: Record<string, unknown>): Engagement {
  return EngagementSchema.parse({
    version: 1,
    id: 'compile-case',
    name: 'Compile case',
    type: 'pentest',
    client: 'Example Client',
    authorization: { reference: 'AL-1', authorised_by: 'A. Signer', signed_on: '2026-10-01' },
    window: { start: '2026-10-01T00:00:00Z', end: '2026-12-31T00:00:00Z', timezone: 'UTC' },
    scope,
  })
}

describe('compileScope', () => {
  it('sorts entries into ranges, host patterns and URLs with list-indexed text', () => {
    const { scope, issues } = compileScope(
      engagement({
        in: [
          '192.0.2.0/25',
          '192.0.2.200-192.0.2.210',
          '2001:db8:ac::/48',
          'Acme.Example.',
          '*.acme.example',
          { target: 'https://portal.acme.example:8443/app', note: 'partner portal' },
          'http://192.0.2.5',
        ],
        out: ['vpn.acme.example'],
        operator_infrastructure: ['198.51.100.10'],
      }),
    )
    expect(issues).toEqual([])
    expect(scope.in.ranges).toEqual([
      { range: parseCidr('192.0.2.0/25'), text: 'in[0]: 192.0.2.0/25' },
      {
        range: { family: 4, start: 0xc00002c8n, end: 0xc00002d2n },
        text: 'in[1]: 192.0.2.200-192.0.2.210',
      },
      { range: parseCidr('2001:db8:ac::/48'), text: 'in[2]: 2001:db8:ac::/48' },
    ])
    expect(scope.in.hosts).toEqual([
      { pattern: { kind: 'exact', host: 'acme.example' }, text: 'in[3]: Acme.Example.' },
      { pattern: { kind: 'wildcard', suffix: 'acme.example' }, text: 'in[4]: *.acme.example' },
    ])
    expect(scope.in.urls).toEqual([
      {
        scheme: 'https',
        host: 'portal.acme.example',
        port: 8443,
        pathPrefix: '/app/',
        text: 'in[5]: https://portal.acme.example:8443/app',
      },
      {
        scheme: 'http',
        host: '192.0.2.5',
        port: 80,
        pathPrefix: '/',
        text: 'in[6]: http://192.0.2.5',
      },
    ])
    expect(scope.out.hosts.map((h) => h.text)).toEqual(['out[0]: vpn.acme.example'])
    expect(scope.operator.ranges.map((r) => r.text)).toEqual([
      'operator_infrastructure[0]: 198.51.100.10',
    ])
    expect(scope.out.ranges).toEqual([])
    expect(scope.operator.urls).toEqual([])
  })

  it('drops query and fragment from a URL path prefix', () => {
    const { scope } = compileScope(engagement({ in: ['https://acme.example/app/x?y=1#z'] }))
    expect(scope.in.urls[0]?.pathPrefix).toBe('/app/x/')
  })

  it('reports SCOPE_ENTRY_INVALID at scope.<list>[i] for anything that is not a scope entry', () => {
    const bad = [
      '300.1.1.1',
      '192.0.2.0/33',
      'acme.example:8443',
      'acme.example/app/',
      'https://user:pw@acme.example/',
      'gopher://acme.example/',
      'not a host',
      '*',
      'a.*.example',
    ]
    const { scope, issues } = compileScope(
      engagement({ in: ['acme.example'], out: bad, operator_infrastructure: [{ target: '-x' }] }),
    )
    expect(issues.map((i) => [i.severity, i.code, i.path])).toEqual([
      ...bad.map((_, i) => ['error', 'SCOPE_ENTRY_INVALID', `scope.out[${i}]`]),
      ['error', 'SCOPE_ENTRY_INVALID', 'scope.operator_infrastructure[0]'],
    ])
    expect(issues[0]?.message).toContain('300.1.1.1')
    expect(scope.out).toEqual({ ranges: [], hosts: [], urls: [] })
  })
})
