import { describe, expect, it } from 'vitest'
import { hostMatches } from '../../src/scope/hostname.js'
import { parseIp, rangeContains } from '../../src/scope/ip.js'
import { compileTrustedInfra, DEFAULT_TRUSTED_INFRA } from '../../src/scope/trusted-infra.js'

const point = (s: string) => {
  const a = parseIp(s)
  if (a === undefined) throw new Error(`bad ip ${s}`)
  return { family: a.family, start: a.value, end: a.value }
}

describe('DEFAULT_TRUSTED_INFRA', () => {
  it('is the conservative default list from the spec (§10)', () => {
    expect(DEFAULT_TRUSTED_INFRA).toEqual([
      'github.com',
      '*.github.com',
      '*.githubusercontent.com',
      'ghcr.io',
      'registry.npmjs.org',
      'pypi.org',
      'files.pythonhosted.org',
      'crates.io',
      'static.crates.io',
      'proxy.golang.org',
      'sum.golang.org',
      'deb.debian.org',
      'security.debian.org',
      'http.kali.org',
      'archive.ubuntu.com',
      'security.ubuntu.com',
      'dl-cdn.alpinelinux.org',
      'registry-1.docker.io',
      'auth.docker.io',
      'production.cloudflare.docker.com',
      'gitlab.com',
      'bitbucket.org',
      'rubygems.org',
      'repo.maven.apache.org',
      '1.1.1.1',
      '1.0.0.1',
      '8.8.8.8',
      '8.8.4.4',
      '9.9.9.9',
      '2606:4700:4700::1111',
      '2001:4860:4860::8888',
    ])
  })

  it('cannot be modified at runtime', () => {
    expect(Object.isFrozen(DEFAULT_TRUSTED_INFRA)).toBe(true)
  })
})

describe('compileTrustedInfra', () => {
  const list = compileTrustedInfra()

  it('compiles names and addresses with trusted[i] rule texts', () => {
    expect(list.hosts.map((h) => h.text)).toContain('trusted[0]: github.com')
    expect(list.ranges.map((r) => r.text)).toContain('trusted[26]: 8.8.8.8')
    expect(list.urls).toEqual([])
    expect(list.hosts.length + list.ranges.length).toBe(DEFAULT_TRUSTED_INFRA.length)
  })

  it('matches by name and address only', () => {
    const hostHit = (h: string) => list.hosts.some((e) => hostMatches(e.pattern, h))
    const ipHit = (s: string) => list.ranges.some((e) => rangeContains(e.range, point(s)))
    expect(hostHit('github.com')).toBe(true)
    expect(hostHit('codeload.github.com')).toBe(true)
    expect(hostHit('raw.githubusercontent.com')).toBe(true)
    expect(hostHit('githubusercontent.com')).toBe(false)
    expect(hostHit('github.com.attacker.example')).toBe(false)
    expect(hostHit('evilgithub.com')).toBe(false)
    expect(ipHit('8.8.8.8')).toBe(true)
    expect(ipHit('2001:4860:4860::8888')).toBe(true)
    expect(ipHit('8.8.8.9')).toBe(false)
  })

  it('accepts a custom list and refuses entries that do not compile', () => {
    const custom = compileTrustedInfra(['mirror.example', '203.0.113.5'])
    expect(custom.hosts.map((h) => h.text)).toEqual(['trusted[0]: mirror.example'])
    expect(custom.ranges.map((r) => r.text)).toEqual(['trusted[1]: 203.0.113.5'])
    expect(() => compileTrustedInfra(['not a host!'])).toThrow(/trusted\[0\]/)
  })
})
