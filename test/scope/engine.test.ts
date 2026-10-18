import dns from 'node:dns'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest'
import { parse as parseYaml, stringify as stringifyYaml } from 'yaml'
import { type LoadedCase, parseEngagement } from '../../src/engagement/load.js'
import { type ClassifyOptions, createScopeEngine } from '../../src/scope/engine.js'
import { type IpRange, parseIp, parseIpSpec } from '../../src/scope/ip.js'
import { createResolver, type LookupFn, type Resolver } from '../../src/scope/resolver.js'
import { parseTarget } from '../../src/scope/target.js'
import { compileTrustedInfra } from '../../src/scope/trusted-infra.js'

const FIXTURE = join(import.meta.dirname, '..', 'fixtures', 'engagements', 'acme-external.yaml')
const IN_WINDOW = new Date('2026-10-22T12:00:00Z')

type Answer = { address: string; family: 4 | 6 }
const a4 = (address: string): Answer => ({ address, family: 4 })
const a6 = (address: string): Answer => ({ address, family: 6 })

/** Every name the tests resolve. Anything else rejects like ENOTFOUND. */
const DNS: Record<string, Answer[] | Error> = {
  'acme.example': [a4('192.0.2.10')],
  'www.acme.example': [a4('192.0.2.20')],
  'v6.acme.example': [a6('2001:db8:ac::5')],
  'mail.acme.example': [a4('192.0.2.66')],
  'intranet.acme.example': [a4('10.0.0.5')],
  'cdn.acme.example': [a4('203.0.113.40')],
  'dual.acme.example': [a4('192.0.2.30'), a4('203.0.113.41')],
  'ghost.acme.example': new Error('getaddrinfo ENOTFOUND ghost.acme.example'),
  'portal.acme-partner.example': [a4('203.0.113.80')],
  'rebind.attacker.example': [a4('192.0.2.66')],
  'loop.attacker.example': [a4('127.0.0.1')],
  'zero.attacker.example': [a4('0.0.0.0')],
  'nat64.attacker.example': [a6('64:ff9b::a00:5')],
  'other.example': [a4('203.0.113.9')],
  'github.com': [a4('203.0.113.100')],
  'c2.operator.example': [a4('198.51.100.20')],
  // Ruling P13: split-horizon mirrors of trusted names, and rebinding shapes.
  'registry.npmjs.org': [a4('10.20.0.5')],
  'pypi.org': [a4('169.254.169.254')],
  'ghcr.io': [a4('127.0.0.1')],
  'crates.io': [a6('fd00::5')],
  'proxy.golang.org': [a4('100.64.0.5')],
  'sum.golang.org': [a6('fe80::1')],
  'deb.debian.org': [a4('0.0.0.0')],
  'security.debian.org': [a4('192.0.2.66')],
  'vpn.operator.example': [a4('10.8.0.1')],
  'jump.operator.example': [a4('10.9.0.1')],
}

function fakeLookup(map: Record<string, Answer[] | Error>) {
  const calls: string[] = []
  const lookup: LookupFn = async (host) => {
    calls.push(host)
    const answer = map[host]
    if (answer === undefined) throw new Error(`getaddrinfo ENOTFOUND ${host}`)
    if (answer instanceof Error) throw answer
    return answer
  }
  return { lookup, calls }
}

function loadCase(mutate?: (doc: Record<string, any>) => void): LoadedCase {
  const doc = parseYaml(readFileSync(FIXTURE, 'utf8'))
  mutate?.(doc)
  const r = parseEngagement(stringifyYaml(doc), 'acme-external.yaml', { now: IN_WINDOW })
  if (!r.ok) throw new Error(JSON.stringify(r.issues))
  return r.case
}

function engineFor(case_: LoadedCase, resolver: Resolver) {
  const engine = createScopeEngine({ case: case_, resolver, trusted: compileTrustedInfra() })
  return (raw: string, o: Partial<ClassifyOptions> = {}) => {
    const t = parseTarget(raw)
    if (t === undefined) throw new Error(`not a target: ${raw}`)
    return engine.classify(t, { httpTool: false, excludes: [], ...o })
  }
}

function setup(mutate?: (doc: Record<string, any>) => void) {
  const { lookup, calls } = fakeLookup(DNS)
  const resolver = createResolver({ lookup, now: () => 0 })
  const classify = engineFor(loadCase(mutate), resolver)
  return { resolver, calls, classify }
}

const ip = (s: string) => {
  const a = parseIp(s)
  if (a === undefined) throw new Error(`bad ip ${s}`)
  return a
}
const range = (s: string): IpRange => {
  const r = parseIpSpec(s)
  if (r === undefined) throw new Error(`bad range ${s}`)
  return r
}

// Real DNS must never be reached from a unit test.
let realDns: MockInstance
beforeEach(() => {
  realDns = vi.spyOn(dns.promises, 'lookup').mockImplementation(() => {
    throw new Error('real DNS lookup attempted in a unit test')
  })
})
afterEach(() => {
  expect(realDns).not.toHaveBeenCalled()
  vi.restoreAllMocks()
})

describe('ScopeEngine: IP targets', () => {
  it('returns a complete verdict for an in-scope address', async () => {
    const { classify } = setup()
    const v = await classify('192.0.2.10')
    expect(v).toEqual({
      target: parseTarget('192.0.2.10'),
      class: 'in-scope',
      reason: 'IN_SCOPE',
      rule: 'in[2]: 192.0.2.0/25',
      resolved: [],
      derivedVia: null,
    })
  })

  it.each([
    ['192.0.2.10', 'in-scope', 'IN_SCOPE', 'in[2]: 192.0.2.0/25'],
    ['2001:db8:ac::1', 'in-scope', 'IN_SCOPE', 'in[3]: 2001:db8:ac::/48'],
    ['192.0.2.66', 'out-of-scope', 'OUT_OF_SCOPE', 'out[2]: 192.0.2.66'],
    ['::ffff:192.0.2.66', 'out-of-scope', 'OUT_OF_SCOPE', 'out[2]: 192.0.2.66'],
    ['64:ff9b::192.0.2.66', 'out-of-scope', 'OUT_OF_SCOPE', 'out[2]: 192.0.2.66'],
    ['192.0.2.200', 'unknown', 'UNKNOWN_TARGET', null],
    ['127.0.0.1', 'local', 'LOCAL_TARGET', null],
    ['::1', 'local', 'LOCAL_TARGET', null],
    ['0.0.0.0', 'local', 'LOCAL_TARGET', null],
    ['::', 'local', 'LOCAL_TARGET', null],
    [
      '198.51.100.10',
      'operator-infra',
      'OPERATOR_INFRA',
      'operator_infrastructure[0]: 198.51.100.10',
    ],
    ['8.8.8.8', 'trusted-infra', 'TRUSTED_INFRA', 'trusted[26]: 8.8.8.8'],
    ['10.1.2.3', 'unknown', 'UNKNOWN_TARGET', null],
    // NAT64 reaches the translator, not this host, so an embedded loopback is not 'local'.
    ['64:ff9b::127.0.0.1', 'unknown', 'UNKNOWN_TARGET', null],
  ])('%s is %s (%s)', async (raw, cls, reason, rule) => {
    const { classify } = setup()
    expect(await classify(raw)).toMatchObject({ class: cls, reason, rule })
  })

  it('keeps out ahead of local and in', async () => {
    const { classify } = setup((d) => {
      d.scope.out.push('127.0.0.1')
    })
    expect(await classify('127.0.0.1')).toMatchObject({
      class: 'out-of-scope',
      rule: 'out[3]: 127.0.0.1',
    })
  })

  it('puts private addresses in scope only via an in entry, or on an internal case that allows them', async () => {
    const covered = setup((d) => {
      d.profile = 'internal'
      d.scope.in.push('10.0.0.0/8')
    })
    expect(await covered.classify('10.1.2.3')).toMatchObject({
      class: 'in-scope',
      rule: 'in[5]: 10.0.0.0/8',
    })

    const internalNoAllow = setup((d) => {
      d.profile = 'internal'
    })
    expect(await internalNoAllow.classify('10.1.2.3')).toMatchObject({ class: 'unknown' })

    const externalAllow = setup((d) => {
      d.scope.allow_private_targets = true
    })
    expect(await externalAllow.classify('10.1.2.3')).toMatchObject({ class: 'unknown' })

    const internalAllow = setup((d) => {
      d.profile = 'internal'
      d.scope.allow_private_targets = true
    })
    expect(await internalAllow.classify('10.1.2.3')).toMatchObject({
      class: 'in-scope',
      reason: 'IN_SCOPE',
      rule: 'scope.allow_private_targets',
    })
    expect(await internalAllow.classify('8.8.4.4')).toMatchObject({ class: 'trusted-infra' })
  })

  it('treats an IP derived from an in-scope name as in scope, with derivedVia', async () => {
    const { classify } = setup((d) => {
      d.scope.require_ip_match = false
    })
    expect(await classify('203.0.113.40')).toMatchObject({ class: 'unknown', derivedVia: null })
    expect(await classify('cdn.acme.example')).toMatchObject({ class: 'in-scope' })
    expect(await classify('203.0.113.40')).toMatchObject({
      class: 'in-scope',
      reason: 'IN_SCOPE',
      derivedVia: 'cdn.acme.example',
    })
  })
})

describe("ScopeEngine: derived IPs are re-checked against the engine's own case", () => {
  const noIpMatch = (d: Record<string, any>) => {
    d.scope.require_ip_match = false
  }

  function shared() {
    const { lookup } = fakeLookup(DNS)
    const resolver = createResolver({ lookup, now: () => 0 })
    const before = engineFor(loadCase(noIpMatch), resolver)
    return { resolver, before }
  }

  it('drops a derivation whose name the edited case moved to out', async () => {
    const { resolver, before } = shared()
    expect(await before('cdn.acme.example')).toMatchObject({ class: 'in-scope' })
    expect(resolver.derivedFrom(ip('203.0.113.40'))).toBe('cdn.acme.example')
    const after = engineFor(
      loadCase((d) => {
        noIpMatch(d)
        d.scope.out.push('cdn.acme.example')
      }),
      resolver,
    )
    expect(await after('203.0.113.40')).toMatchObject({
      class: 'unknown',
      reason: 'UNKNOWN_TARGET',
      derivedVia: null,
    })
    expect(await before('203.0.113.40')).toMatchObject({ derivedVia: 'cdn.acme.example' })
  })

  it('drops a derivation whose name the edited case no longer lists in in', async () => {
    const { resolver, before } = shared()
    await before('cdn.acme.example')
    const after = engineFor(
      loadCase((d) => {
        noIpMatch(d)
        d.scope.in = d.scope.in.filter((x: string) => x !== '*.acme.example')
      }),
      resolver,
    )
    expect(await after('203.0.113.40')).toMatchObject({ class: 'unknown', derivedVia: null })
  })

  it('drops a derivation that the edited case would now refuse with require_ip_match', async () => {
    const { resolver, before } = shared()
    await before('cdn.acme.example')
    const after = engineFor(loadCase(), resolver)
    expect(await after('203.0.113.40')).toMatchObject({ class: 'unknown', derivedVia: null })
  })

  it('drops a private derivation on a case that is no longer internal', async () => {
    const { lookup } = fakeLookup(DNS)
    const resolver = createResolver({ lookup, now: () => 0 })
    const internal = engineFor(
      loadCase((d) => {
        noIpMatch(d)
        d.profile = 'internal'
      }),
      resolver,
    )
    expect(await internal('intranet.acme.example')).toMatchObject({ class: 'in-scope' })
    expect(await internal('10.0.0.5')).toMatchObject({ derivedVia: 'intranet.acme.example' })
    const external = engineFor(loadCase(noIpMatch), resolver)
    expect(await external('10.0.0.5')).toMatchObject({ class: 'unknown', derivedVia: null })
  })
})

describe('ScopeEngine: RESOLVES_PRIVATE for trusted and operator names (ruling P13)', () => {
  it('allows a trusted name whose answer is a split-horizon private mirror', async () => {
    const { classify } = setup()
    for (const [name, answer] of [
      ['registry.npmjs.org', '10.20.0.5'],
      ['crates.io', 'fd00::5'],
      ['proxy.golang.org', '100.64.0.5'],
    ] as const) {
      expect(await classify(name)).toMatchObject({
        class: 'trusted-infra',
        reason: 'TRUSTED_INFRA',
        resolved: [ip(answer)],
      })
    }
  })

  it('still denies a trusted name answering loopback, link-local or unspecified', async () => {
    const { classify } = setup()
    for (const [name, answer] of [
      ['pypi.org', '169.254.169.254'],
      ['ghcr.io', '127.0.0.1'],
      ['sum.golang.org', 'fe80::1'],
      ['deb.debian.org', '0.0.0.0'],
    ] as const) {
      expect(await classify(name)).toMatchObject({
        class: 'out-of-scope',
        reason: 'RESOLVES_PRIVATE',
        resolved: [ip(answer)],
      })
    }
  })

  it('still denies a trusted name resolving into out', async () => {
    const { classify } = setup()
    expect(await classify('security.debian.org')).toMatchObject({
      reason: 'RESOLVES_OUT_OF_SCOPE',
      rule: 'out[2]: 192.0.2.66',
    })
  })

  it('does not relax the rail for a trusted name the case lists as a target', async () => {
    const { classify } = setup((d) => {
      d.scope.in.push('registry.npmjs.org')
    })
    expect(await classify('registry.npmjs.org')).toMatchObject({ reason: 'RESOLVES_PRIVATE' })
  })

  it("exempts an operator name's answers inside the case's operator ranges only", async () => {
    const { classify } = setup((d) => {
      d.scope.operator_infrastructure.push(
        '10.8.0.0/24',
        'vpn.operator.example',
        'jump.operator.example',
      )
    })
    expect(await classify('vpn.operator.example')).toMatchObject({
      class: 'operator-infra',
      reason: 'OPERATOR_INFRA',
      rule: 'operator_infrastructure[2]: vpn.operator.example',
      resolved: [ip('10.8.0.1')],
    })
    expect(await classify('jump.operator.example')).toMatchObject({
      class: 'out-of-scope',
      reason: 'RESOLVES_PRIVATE',
    })
  })

  it('does not extend the operator exemption to other names', async () => {
    const { classify } = setup((d) => {
      d.scope.operator_infrastructure.push('10.8.0.0/24')
    })
    expect(await classify('vpn.operator.example')).toMatchObject({ reason: 'RESOLVES_PRIVATE' })
  })
})

describe('ScopeEngine: ranges (Review Focus 4)', () => {
  it('denies a range that reaches an out entry', async () => {
    const { classify } = setup()
    expect(await classify('192.0.2.0/25')).toMatchObject({
      class: 'out-of-scope',
      reason: 'OUT_OF_SCOPE',
      rule: 'out[2]: 192.0.2.66',
    })
    // /24 also contains 192.0.2.66; out wins over "not fully authorised".
    expect(await classify('192.0.2.0/24')).toMatchObject({ reason: 'OUT_OF_SCOPE' })
  })

  it("puts the range in scope once the command's own --exclude removes the out address", async () => {
    const { classify } = setup()
    expect(await classify('192.0.2.0/25', { excludes: [range('192.0.2.66')] })).toMatchObject({
      class: 'in-scope',
      reason: 'IN_SCOPE',
      rule: 'in[2]: 192.0.2.0/25',
    })
  })

  it('asks when the range is only partly covered by in', async () => {
    const { classify } = setup()
    expect(await classify('192.0.2.0/24', { excludes: [range('192.0.2.66')] })).toMatchObject({
      class: 'unknown',
      reason: 'RANGE_NOT_FULLY_AUTHORISED',
    })
    expect(await classify('192.0.2.0/26')).toMatchObject({ class: 'in-scope', reason: 'IN_SCOPE' })
  })

  it('ignores excludes of the other family', async () => {
    const { classify } = setup()
    expect(await classify('192.0.2.0/25', { excludes: [range('2001:db8::/32')] })).toMatchObject({
      reason: 'OUT_OF_SCOPE',
    })
  })

  it('sees an IPv4 out entry inside an IPv6 range through the mapped and NAT64 blocks', async () => {
    const { classify } = setup()
    expect(await classify('::/0')).toMatchObject({
      reason: 'OUT_OF_SCOPE',
      rule: 'out[2]: 192.0.2.66',
    })
    expect(await classify('64:ff9b::/96')).toMatchObject({ reason: 'OUT_OF_SCOPE' })
  })

  it('treats an all-loopback range as local', async () => {
    const { classify } = setup()
    expect(await classify('127.0.0.0/8')).toMatchObject({ class: 'local', reason: 'LOCAL_TARGET' })
    expect(await classify('127.0.0.0/7')).toMatchObject({ class: 'unknown' })
  })

  it('asks when the excludes remove every address', async () => {
    const { classify } = setup()
    expect(await classify('192.0.2.0/30', { excludes: [range('192.0.2.0/24')] })).toMatchObject({
      class: 'unknown',
      reason: 'RANGE_NOT_FULLY_AUTHORISED',
    })
  })
})

describe('ScopeEngine: hostnames and DNS guard rails', () => {
  it('puts a name that matches in and resolves into in ranges in scope, and records derived IPs', async () => {
    const { classify, resolver } = setup()
    expect(await classify('www.acme.example')).toEqual({
      target: parseTarget('www.acme.example'),
      class: 'in-scope',
      reason: 'IN_SCOPE',
      rule: 'in[1]: *.acme.example',
      resolved: [ip('192.0.2.20')],
      derivedVia: null,
    })
    expect(resolver.derivedFrom(ip('192.0.2.20'))).toBe('www.acme.example')
    expect(await classify('acme.example')).toMatchObject({
      class: 'in-scope',
      rule: 'in[0]: acme.example',
    })
    expect(await classify('v6.acme.example')).toMatchObject({ class: 'in-scope' })
  })

  it('denies a name that resolves into out', async () => {
    const { classify, resolver } = setup()
    expect(await classify('mail.acme.example')).toMatchObject({
      class: 'out-of-scope',
      reason: 'RESOLVES_OUT_OF_SCOPE',
      rule: 'out[2]: 192.0.2.66',
      resolved: [ip('192.0.2.66')],
    })
    expect(await classify('rebind.attacker.example')).toMatchObject({
      reason: 'RESOLVES_OUT_OF_SCOPE',
    })
    expect(resolver.derivedFrom(ip('192.0.2.66'))).toBeUndefined()
  })

  it('denies a private resolution on a non-internal case', async () => {
    const { classify } = setup()
    expect(await classify('intranet.acme.example')).toMatchObject({
      class: 'out-of-scope',
      reason: 'RESOLVES_PRIVATE',
      resolved: [ip('10.0.0.5')],
    })
    expect(await classify('loop.attacker.example')).toMatchObject({ reason: 'RESOLVES_PRIVATE' })
    expect(await classify('zero.attacker.example')).toMatchObject({ reason: 'RESOLVES_PRIVATE' })
    expect(await classify('nat64.attacker.example')).toMatchObject({ reason: 'RESOLVES_PRIVATE' })
  })

  it('allows a private resolution that an in entry covers, or on an internal case', async () => {
    const covered = setup((d) => {
      d.scope.in.push('10.0.0.0/24')
    })
    expect(await covered.classify('intranet.acme.example')).toMatchObject({ class: 'in-scope' })
    const internal = setup((d) => {
      d.profile = 'internal'
      d.scope.require_ip_match = false
    })
    expect(await internal.classify('intranet.acme.example')).toMatchObject({ class: 'in-scope' })
  })

  it('asks when an in-scope name resolves outside in ranges with require_ip_match', async () => {
    const { classify, resolver } = setup()
    expect(await classify('cdn.acme.example')).toMatchObject({
      class: 'unknown',
      reason: 'THIRD_PARTY_HOSTING',
      rule: 'in[1]: *.acme.example',
      resolved: [ip('203.0.113.40')],
    })
    expect(await classify('dual.acme.example')).toMatchObject({ reason: 'THIRD_PARTY_HOSTING' })
    expect(resolver.derivedFrom(ip('203.0.113.40'))).toBeUndefined()
    expect(resolver.derivedFrom(ip('192.0.2.30'))).toBeUndefined()
  })

  it('asks when an in-scope name does not resolve', async () => {
    const { classify } = setup()
    expect(await classify('ghost.acme.example')).toMatchObject({
      class: 'unknown',
      reason: 'UNRESOLVABLE',
      rule: 'in[1]: *.acme.example',
      resolved: [],
    })
  })

  it('denies an out name without any lookup', async () => {
    const { classify, calls } = setup()
    expect(await classify('x.corp.acme.example')).toMatchObject({
      class: 'out-of-scope',
      reason: 'OUT_OF_SCOPE',
      rule: 'out[1]: *.corp.acme.example',
      resolved: [],
    })
    expect(await classify('vpn.acme.example')).toMatchObject({ rule: 'out[0]: vpn.acme.example' })
    expect(calls).toEqual([])
  })

  it('treats localhost and *.localhost as local without a lookup', async () => {
    const { classify, calls } = setup()
    expect(await classify('localhost')).toMatchObject({ class: 'local', reason: 'LOCAL_TARGET' })
    expect(await classify('app.localhost:3000')).toMatchObject({ class: 'local' })
    expect(calls).toEqual([])
  })

  it('classifies operator and trusted names by name, after the case lists', async () => {
    const { classify, calls } = setup((d) => {
      d.scope.operator_infrastructure.push('c2.operator.example')
    })
    expect(await classify('c2.operator.example')).toMatchObject({
      class: 'operator-infra',
      reason: 'OPERATOR_INFRA',
      rule: 'operator_infrastructure[1]: c2.operator.example',
    })
    expect(await classify('github.com')).toMatchObject({
      class: 'trusted-infra',
      reason: 'TRUSTED_INFRA',
      rule: 'trusted[0]: github.com',
    })
    expect(await classify('other.example')).toMatchObject({
      class: 'unknown',
      reason: 'UNKNOWN_TARGET',
    })
    // Every hostname is resolved while a case is active (§6.3).
    expect(calls).toEqual(['c2.operator.example', 'github.com', 'other.example'])
  })

  it('lets the case classify a trusted host it lists', async () => {
    const { classify } = setup((d) => {
      d.scope.out.push('github.com')
    })
    expect(await classify('github.com')).toMatchObject({
      reason: 'OUT_OF_SCOPE',
      rule: 'out[3]: github.com',
    })
  })

  it('never uses PTR: an in-scope IP gives no name', async () => {
    const { classify, calls } = setup()
    expect(await classify('192.0.2.20')).toMatchObject({ derivedVia: null })
    expect(calls).toEqual([])
  })
})

describe('ScopeEngine: URLs', () => {
  const PORTAL = 'https://portal.acme-partner.example:8443'

  it('puts an HTTP request under an in URL entry in scope', async () => {
    const { classify, resolver } = setup()
    expect(await classify(`${PORTAL}/app/login`, { httpTool: true })).toMatchObject({
      class: 'in-scope',
      reason: 'IN_SCOPE',
      rule: 'in[4]: https://portal.acme-partner.example:8443/app/',
      resolved: [ip('203.0.113.80')],
    })
    expect(await classify(`${PORTAL}/app`, { httpTool: true })).toMatchObject({ class: 'in-scope' })
    // A URL-only authorisation never widens to the host's addresses.
    expect(resolver.derivedFrom(ip('203.0.113.80'))).toBeUndefined()
  })

  it.each([
    ['another path', `${PORTAL}/admin`, true],
    ['a sibling prefix', `${PORTAL}/application`, true],
    ['another port', 'https://portal.acme-partner.example/app/login', true],
    ['another scheme', 'http://portal.acme-partner.example:8443/app/login', true],
    ['a non-HTTP tool', `${PORTAL}/app/login`, false],
    ['a bare host', 'portal.acme-partner.example', true],
  ])('asks for %s, naming the authorised URL', async (_label, raw, httpTool) => {
    const { classify } = setup()
    const v = await classify(raw, { httpTool })
    expect(v).toMatchObject({ class: 'unknown', reason: 'UNKNOWN_TARGET' })
    expect(v.rule).toContain('authorised only as https://portal.acme-partner.example:8443/app/')
  })

  it('checks other URLs as their host or IP', async () => {
    const { classify } = setup()
    expect(await classify('https://www.acme.example/x', { httpTool: true })).toMatchObject({
      class: 'in-scope',
      rule: 'in[1]: *.acme.example',
    })
    expect(await classify('https://vpn.acme.example/', { httpTool: true })).toMatchObject({
      reason: 'OUT_OF_SCOPE',
    })
    expect(await classify('http://192.0.2.10:8080/', { httpTool: true })).toMatchObject({
      class: 'in-scope',
      rule: 'in[2]: 192.0.2.0/25',
    })
    expect(await classify('http://[::1]:3000/', { httpTool: true })).toMatchObject({
      class: 'local',
    })
  })

  it('matches an IP-host URL against an in URL entry for that IP', async () => {
    const { classify } = setup((d) => {
      d.scope.in.push('https://203.0.113.50:8443/api/')
    })
    expect(await classify('https://203.0.113.50:8443/api/v1', { httpTool: true })).toMatchObject({
      class: 'in-scope',
      reason: 'IN_SCOPE',
      rule: 'in[5]: https://203.0.113.50:8443/api/',
      resolved: [],
    })
    const other = await classify('https://203.0.113.50:8443/admin', { httpTool: true })
    expect(other).toMatchObject({ class: 'unknown', reason: 'UNKNOWN_TARGET' })
    expect(other.rule).toContain('authorised only as https://203.0.113.50:8443/api/')
    expect(await classify('203.0.113.50')).toMatchObject({ class: 'unknown' })
  })

  it('denies a host named by an out URL entry, whatever the path', async () => {
    const { classify } = setup((d) => {
      d.scope.out.push('https://www.acme.example/admin/')
    })
    expect(await classify('www.acme.example')).toMatchObject({
      reason: 'OUT_OF_SCOPE',
      rule: 'out[3]: https://www.acme.example/admin/',
    })
    expect(await classify('https://www.acme.example/', { httpTool: true })).toMatchObject({
      reason: 'OUT_OF_SCOPE',
    })
  })
})
