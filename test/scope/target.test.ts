import { describe, expect, it } from 'vitest'
import { normaliseHostname } from '../../src/scope/hostname.js'
import { parseTarget, targetHost } from '../../src/scope/target.js'

const v4 = (a: number, b: number, c: number, d: number) => ({
  family: 4,
  value: (BigInt(a) << 24n) | (BigInt(b) << 16n) | (BigInt(c) << 8n) | BigInt(d),
})

describe('parseTarget: URLs', () => {
  it('strips credentials and keeps port and path', () => {
    const raw = 'https://user:pw@portal.acme.example:8443/app/x'
    expect(parseTarget(raw)).toEqual({
      kind: 'url',
      raw,
      scheme: 'https',
      host: 'portal.acme.example',
      port: 8443,
      path: '/app/x',
      hadCredentials: true,
    })
  })

  it('parses a bracketed IPv6 URL on the default port', () => {
    const t = parseTarget('http://[2001:db8::5]/')
    expect(t).toMatchObject({
      kind: 'url',
      scheme: 'http',
      host: '2001:db8::5',
      port: 80,
      path: '/',
    })
    if (t?.kind !== 'url') throw new Error('expected url')
    expect(t.ip?.family).toBe(6)
    expect(t.hadCredentials).toBe(false)
  })

  it('uses the scheme default port', () => {
    const t = parseTarget('ssh://192.0.2.10')
    expect(t).toMatchObject({ kind: 'url', scheme: 'ssh', host: '192.0.2.10', port: 22, path: '/' })
    if (t?.kind !== 'url') throw new Error('expected url')
    expect(t.ip).toEqual(v4(192, 0, 2, 10))
  })

  it.each([
    ['http://acme.example', 80],
    ['https://acme.example', 443],
    ['ws://acme.example', 80],
    ['wss://acme.example', 443],
    ['ftp://acme.example', 21],
    ['ssh://acme.example', 22],
    ['smb://acme.example', 445],
    ['ldap://acme.example', 389],
    ['ldaps://acme.example', 636],
    ['rdp://acme.example', 3389],
    ['mysql://acme.example', 3306],
    ['postgres://acme.example', 5432],
    ['redis://acme.example', 6379],
    ['mongodb://acme.example', 27017],
    ['HTTPS://ACME.example:', 443],
    ['http://acme.example:443', 443],
    ['https://acme.example:80/', 80],
  ])('%s -> port %d', (raw, port) => {
    expect(parseTarget(raw)).toMatchObject({ kind: 'url', host: 'acme.example', port })
  })

  it('normalises hosts, IPv4 forms and dot segments like a URL parser', () => {
    expect(parseTarget('http://WWW.Acme.Example./a/../admin?q=1#f')).toMatchObject({
      host: 'www.acme.example',
      path: '/admin',
    })
    expect(parseTarget('http://bücher.example/')).toMatchObject({ host: 'xn--bcher-kva.example' })
    expect(parseTarget('http://0xc0.0.2.10/')).toMatchObject({
      host: '192.0.2.10',
      ip: v4(192, 0, 2, 10),
    })
    expect(parseTarget('http://[::ffff:192.0.2.66]:8080/x')).toMatchObject({
      host: '192.0.2.66',
      ip: v4(192, 0, 2, 66),
      port: 8080,
    })
  })

  it('treats the last @ as the userinfo boundary', () => {
    expect(parseTarget('http://a@b@acme.example/')).toMatchObject({
      host: 'acme.example',
      hadCredentials: true,
    })
    expect(parseTarget('http://acme.example/@203.0.113.5')).toMatchObject({
      host: 'acme.example',
      path: '/@203.0.113.5',
      hadCredentials: false,
    })
  })

  it('keeps the host of an unlisted scheme visible as a host or ip target', () => {
    expect(parseTarget('gopher://203.0.113.5:70/x')).toMatchObject({
      kind: 'ip',
      ip: v4(203, 0, 113, 5),
      port: 70,
    })
    expect(parseTarget('telnet://acme.example')).toEqual({
      kind: 'host',
      raw: 'telnet://acme.example',
      host: 'acme.example',
    })
  })

  it('turns scheme-less host/path into an http URL', () => {
    expect(parseTarget('acme.example/login')).toMatchObject({
      kind: 'url',
      scheme: 'http',
      host: 'acme.example',
      port: 80,
      path: '/login',
      hadCredentials: false,
    })
    expect(parseTarget('192.0.2.10:8080/x')).toMatchObject({
      kind: 'url',
      scheme: 'http',
      ip: v4(192, 0, 2, 10),
      port: 8080,
      path: '/x',
    })
  })

  it.each([
    ['http://'],
    ['http:///x'],
    ['http://user@/x'],
    ['http://acme.example:99999/'],
    ['http://acme.example:8a/'],
    ['http://[2001:db8::5/'],
    ['http://[acme.example]/'],
    ['http://ac me.example/'],
    ['http://evil.example\\@acme.example/'],
    ['file:///etc/passwd'],
    ['./x.example/y'],
    ['/etc/hosts'],
    ['192.0.2.0/33'],
    ['http://acme.example:0/'],
    ['ssh://[2001:db8::5]:0'],
  ])('rejects %j', (raw) => {
    expect(parseTarget(raw)).toBeUndefined()
  })
})

describe('parseTarget: single-slash and bare scheme forms', () => {
  it('reads a known scheme with one slash as scheme:// so the real host is checked', () => {
    expect(parseTarget('http:/evil.example/x')).toEqual({
      kind: 'url',
      raw: 'http:/evil.example/x',
      scheme: 'http',
      host: 'evil.example',
      port: 80,
      path: '/x',
      hadCredentials: false,
    })
    expect(parseTarget('HTTPS:/user:pw@evil.example:8443')).toMatchObject({
      kind: 'url',
      scheme: 'https',
      host: 'evil.example',
      port: 8443,
      hadCredentials: true,
    })
    expect(parseTarget('ssh:/203.0.113.5')).toMatchObject({
      kind: 'url',
      host: '203.0.113.5',
      ip: v4(203, 0, 113, 5),
      port: 22,
    })
  })

  it.each([
    ['http:evil.example'],
    ['http:evil.example/x'],
    ['http:/'],
    ['http:/\\evil.example/'],
    ['gopher:/evil.example/x'],
    ['acme.example:/x'],
    ['http:'],
  ])('rejects %j and never yields the scheme as a host', (raw) => {
    expect(parseTarget(raw)).toBeUndefined()
  })

  it('still parses real host:port near-misses', () => {
    expect(parseTarget('acme.example:8080')).toMatchObject({
      kind: 'host',
      host: 'acme.example',
      port: 8080,
    })
    expect(parseTarget('acme.example:8080/x')).toMatchObject({
      kind: 'url',
      host: 'acme.example',
      port: 8080,
      path: '/x',
    })
    expect(parseTarget('http.acme.example:80/x')).toMatchObject({
      kind: 'url',
      host: 'http.acme.example',
      port: 80,
    })
  })
})

describe('parseTarget: IPs, ranges and hosts', () => {
  it('parses a bare IP', () => {
    expect(parseTarget('192.0.2.10')).toEqual({
      kind: 'ip',
      raw: '192.0.2.10',
      ip: v4(192, 0, 2, 10),
    })
    expect(parseTarget('2001:db8::5')).toMatchObject({ kind: 'ip', ip: { family: 6 } })
  })

  it('parses ip:port and [v6]:port', () => {
    expect(parseTarget('192.0.2.10:443')).toEqual({
      kind: 'ip',
      raw: '192.0.2.10:443',
      ip: v4(192, 0, 2, 10),
      port: 443,
    })
    expect(parseTarget('[2001:db8::5]:8443')).toMatchObject({
      kind: 'ip',
      ip: { family: 6 },
      port: 8443,
    })
    expect(parseTarget('[2001:db8::5]')).toMatchObject({ kind: 'ip', ip: { family: 6 } })
    expect(parseTarget('[2001:db8::5]')).not.toHaveProperty('port')
  })

  it('parses host and host:port', () => {
    expect(parseTarget('acme.example:22')).toEqual({
      kind: 'host',
      raw: 'acme.example:22',
      host: 'acme.example',
      port: 22,
    })
    expect(parseTarget('Portal.ACME.example.')).toEqual({
      kind: 'host',
      raw: 'Portal.ACME.example.',
      host: 'portal.acme.example',
    })
  })

  it('parses CIDRs and ranges', () => {
    expect(parseTarget('192.0.2.0/25')).toEqual({
      kind: 'range',
      raw: '192.0.2.0/25',
      range: { family: 4, start: v4(192, 0, 2, 0).value, end: v4(192, 0, 2, 127).value },
    })
    expect(parseTarget('192.0.2.10-192.0.2.20')).toMatchObject({
      kind: 'range',
      range: { family: 4, start: v4(192, 0, 2, 10).value, end: v4(192, 0, 2, 20).value },
    })
    expect(parseTarget('2001:db8::/64')).toMatchObject({ kind: 'range', range: { family: 6 } })
  })

  it('canonicalises legacy numeric IPv4 forms instead of dropping them', () => {
    expect(parseTarget('3221225994')).toMatchObject({ kind: 'ip', ip: v4(192, 0, 2, 10) })
    expect(parseTarget('16777216')).toMatchObject({ kind: 'ip', ip: v4(1, 0, 0, 0) })
    expect(parseTarget('0x50')).toMatchObject({ kind: 'ip', ip: v4(0, 0, 0, 80) })
    expect(parseTarget('0xc0.0.2.10:80')).toMatchObject({
      kind: 'ip',
      ip: v4(192, 0, 2, 10),
      port: 80,
    })
  })

  it.each([
    ['--top-ports'],
    ['-'],
    [''],
    ['   '],
    ['-sV'],
    ['acme.example:'],
    ['acme.example:70000'],
    ['acme.example:22:33'],
    ['a b'],
    ['999.1.1.1'],
    ['*.acme.example'],
    ['user@acme.example'],
    ['80'],
    ['65535'],
    ['0'],
    ['16777215'],
    ['80:443'],
    ['acme.example:0'],
    ['192.0.2.10:0'],
    ['[2001:db8::5]:0'],
  ])('rejects %j', (raw) => {
    expect(parseTarget(raw)).toBeUndefined()
  })
})

describe('parseTarget agrees with normaliseHostname', () => {
  it.each([['acme.example。'], ['ACME.Example.'], ['bücher.example'], ['acme.example.。']])(
    '%j',
    (raw) => {
      const t = parseTarget(raw)
      const expected = normaliseHostname(raw)
      if (expected === undefined) {
        expect(t).toBeUndefined()
      } else {
        expect(t).toEqual({ kind: 'host', raw, host: expected })
      }
    },
  )
})

describe('targetHost', () => {
  it.each([
    ['192.0.2.10:443', '192.0.2.10'],
    ['[2001:db8::5]:22', '2001:db8::5'],
    ['acme.example:22', 'acme.example'],
    ['https://user:pw@portal.acme.example:8443/app/x', 'portal.acme.example'],
    ['http://[2001:db8::5]/', '2001:db8::5'],
    ['192.0.2.0/25', '192.0.2.0/25'],
    ['192.0.2.77/25', '192.0.2.0/25'],
    ['192.0.2.10-192.0.2.20', '192.0.2.10-192.0.2.20'],
    ['2001:db8::/64', '2001:db8::/64'],
  ])('%s -> %s', (raw, expected) => {
    const t = parseTarget(raw)
    if (!t) throw new Error(`did not parse ${raw}`)
    expect(targetHost(t)).toBe(expected)
  })
})
