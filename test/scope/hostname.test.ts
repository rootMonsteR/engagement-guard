import { describe, expect, it } from 'vitest'
import {
  FILE_EXTENSIONS,
  hostMatches,
  looksLikeFqdn,
  normaliseHostname,
  parseHostPattern,
} from '../../src/scope/hostname.js'

describe('normaliseHostname', () => {
  it.each([
    ['ACME.Example.', 'acme.example'],
    ['acme.example', 'acme.example'],
    ['bücher.example', 'xn--bcher-kva.example'],
    ['xn--bcher-kva.example', 'xn--bcher-kva.example'],
    ['XN--BCHER-KVA.example', 'xn--bcher-kva.example'],
    ['localhost', 'localhost'],
    ['dc01', 'dc01'],
    ['a-b.c-d.example', 'a-b.c-d.example'],
    [`${'a'.repeat(63)}.example`, `${'a'.repeat(63)}.example`],
    ['acme.example。', 'acme.example'],
    ['ACME．example．', 'acme.example'],
  ])('%s -> %s', (input, expected) => {
    expect(normaliseHostname(input)).toBe(expected)
  })

  it.each([
    ['acme.example.。'],
    ['acme.example。.'],
    ['-a.example'],
    ['a-.example'],
    [`${'a'.repeat(64)}.example`],
    ['a..b'],
    [''],
    ['.'],
    ['acme.example..'],
    ['.acme.example'],
    ['a_b.example'],
    ['*.acme.example'],
    ['a b.example'],
    ['acme.example:80'],
    ['acme.example/x'],
    ['acme.example?x'],
    ['acme.example#x'],
    ['acme.example\\x'],
    ['acme.example／x'],
    ['a@b.example'],
    ['%61cme.example'],
    ['1.2.3'],
    ['0x7f.1'],
    ['192.0.2.10'],
    ['xn--a.example'],
  ])('rejects %j', (input) => {
    expect(normaliseHostname(input)).toBeUndefined()
  })

  it('rejects names longer than 253 characters', () => {
    const label = 'a'.repeat(63)
    const ok = [label, label, label, 'a'.repeat(61)].join('.')
    expect(ok.length).toBe(253)
    expect(normaliseHostname(ok)).toBe(ok)
    expect(normaliseHostname(`a${ok}`)).toBeUndefined()
  })
})

describe('parseHostPattern / hostMatches', () => {
  const wild = parseHostPattern('*.ACME.example')

  it('parses wildcard and exact patterns', () => {
    expect(wild).toEqual({ kind: 'wildcard', suffix: 'acme.example' })
    expect(parseHostPattern('Portal.Acme.Example.')).toEqual({
      kind: 'exact',
      host: 'portal.acme.example',
    })
    expect(parseHostPattern('*.bücher.example')).toEqual({
      kind: 'wildcard',
      suffix: 'xn--bcher-kva.example',
    })
  })

  it.each([
    ['*'],
    ['*.'],
    ['a.*.example'],
    ['*acme.example'],
    ['**.acme.example'],
    ['www.*'],
    [''],
  ])('rejects pattern %j', (input) => {
    expect(parseHostPattern(input)).toBeUndefined()
  })

  it.each([
    ['www.acme.example', true],
    ['a.b.acme.example', true],
    ['WWW.Acme.Example.', true],
    ['acme.example', false],
    ['evilacme.example', false],
    ['acme.example.attacker.example', false],
    ['www.acme.example.attacker.example', false],
    ['', false],
  ])('*.acme.example matches %j -> %s', (host, expected) => {
    if (!wild) throw new Error('pattern did not parse')
    expect(hostMatches(wild, host)).toBe(expected)
  })

  it('exact patterns match only the same normalised host', () => {
    const exact = parseHostPattern('acme.example')
    if (!exact) throw new Error('pattern did not parse')
    expect(hostMatches(exact, 'ACME.example.')).toBe(true)
    expect(hostMatches(exact, 'www.acme.example')).toBe(false)
    expect(hostMatches(exact, 'evilacme.example')).toBe(false)
  })

  it('an IDNA name matches its punycode entry', () => {
    const p = parseHostPattern('xn--bcher-kva.example')
    if (!p) throw new Error('pattern did not parse')
    expect(hostMatches(p, 'bücher.example')).toBe(true)
  })
})

describe('looksLikeFqdn', () => {
  it.each([
    ['portal.acme.example', true],
    ['acme.example', true],
    ['bücher.example', true],
    ['Portal.Acme.Example.', true],
    ['report.json', false],
    ['main.ts', false],
    ['notes.md', false],
    ['archive.tar', false],
    ['1.2.3', false],
    ['192.0.2.10', false],
    ['./x.example/y', false],
    ['x.example/y', false],
    ['x.example\\y', false],
    ['localhost', false],
    ['acme.e', false],
    ['acme.ex4mple', false],
    ['-v.example', false],
    ['', false],
  ])('%j -> %s', (token, expected) => {
    expect(looksLikeFqdn(token)).toBe(expected)
  })

  it('FILE_EXTENSIONS covers common file suffixes', () => {
    for (const ext of ['py', 'js', 'ts', 'json', 'md', 'txt', 'yaml', 'yml', 'xml', 'html']) {
      expect(FILE_EXTENSIONS.has(ext)).toBe(true)
    }
    for (const ext of ['sh', 'ps1', 'exe', 'dll', 'gz', 'tar', 'zip', 'log', 'csv', 'conf']) {
      expect(FILE_EXTENSIONS.has(ext)).toBe(true)
    }
    for (const ext of ['ini', 'pem', 'key', 'mjs', 'cjs', 'lock', 'toml']) {
      expect(FILE_EXTENSIONS.has(ext)).toBe(true)
    }
    expect(FILE_EXTENSIONS.has('example')).toBe(false)
  })
})
