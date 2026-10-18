import { createHash } from 'node:crypto'
import { describe, expect, it } from 'vitest'
import { CanonicalJsonError, canonicalJson, sha256Hex } from '../src/canonical.js'

describe('canonicalJson', () => {
  it('sorts keys recursively and emits no whitespace', () => {
    expect(canonicalJson({ b: 1, a: [{ d: 1, c: 2 }] })).toBe('{"a":[{"c":2,"d":1}],"b":1}')
  })

  it('does not depend on input key order', () => {
    const one = { x: { q: [1, 2, { z: true, y: null }], p: 'v' }, a: 'b' }
    const two = { a: 'b', x: { p: 'v', q: [1, 2, { y: null, z: true }] } }
    expect(canonicalJson(one)).toBe(canonicalJson(two))
  })

  it('keeps array order', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]')
  })

  it('sorts keys by UTF-16 code unit order', () => {
    // 'B' (0x42) < 'a' (0x61) < 'é' (0xe9) < U+1F600 (high surrogate 0xd83d) < U+FF5A (0xff5a).
    // By code point U+1F600 would sort last; by UTF-16 code unit it sorts before U+FF5A.
    const grin = '\u{1F600}'
    const fullwidthZ = 'ｚ'
    const input = { [fullwidthZ]: 5, [grin]: 4, é: 3, a: 2, B: 1 }
    expect(canonicalJson(input)).toBe(`{"B":1,"a":2,"é":3,"${grin}":4,"${fullwidthZ}":5}`)
  })

  it('serialises primitives like JSON', () => {
    expect(canonicalJson(null)).toBe('null')
    expect(canonicalJson(true)).toBe('true')
    expect(canonicalJson(-1.5)).toBe('-1.5')
    expect(canonicalJson('a"b\\c\n')).toBe('"a\\"b\\\\c\\n"')
    expect(canonicalJson({})).toBe('{}')
    expect(canonicalJson([])).toBe('[]')
    expect(canonicalJson(Object.assign(Object.create(null), { b: 2, a: 1 }))).toBe('{"a":1,"b":2}')
  })

  it.each([
    ['undefined at the top level', undefined],
    ['an undefined property', { a: undefined }],
    ['a nested undefined property', { a: { b: [1, { c: undefined }] } }],
    ['an undefined array element', [1, undefined]],
    ['a sparse array hole', [1, , 3]],
    ['a function', { f: () => 1 }],
    ['a symbol', { s: Symbol('x') }],
    ['a bigint', { n: 1n }],
    ['NaN', Number.NaN],
    ['Infinity', { n: Number.POSITIVE_INFINITY }],
    ['-Infinity', [Number.NEGATIVE_INFINITY]],
    ['a Date (not a plain object)', { d: new Date(0) }],
    ['a Map (not a plain object)', new Map([['a', 1]])],
  ])('throws CanonicalJsonError for %s', (_label, value) => {
    expect(() => canonicalJson(value)).toThrow(CanonicalJsonError)
  })

  it('throws CanonicalJsonError for a cycle', () => {
    const a: Record<string, unknown> = {}
    a.self = a
    expect(() => canonicalJson(a)).toThrow(CanonicalJsonError)
  })

  it('accepts a shared (non-cyclic) reference twice', () => {
    const shared = { k: 1 }
    expect(canonicalJson({ a: shared, b: shared })).toBe('{"a":{"k":1},"b":{"k":1}}')
  })

  it('names the path of the offending value', () => {
    expect(() => canonicalJson({ a: [0, { b: undefined }] })).toThrow(/\$\.a\[1\]\.b/)
  })
})

describe('sha256Hex', () => {
  it('hashes a string as UTF-8', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    )
    expect(sha256Hex('é')).toBe(createHash('sha256').update(Buffer.from('é', 'utf8')).digest('hex'))
  })

  it('hashes bytes', () => {
    expect(sha256Hex(new TextEncoder().encode('abc'))).toBe(sha256Hex('abc'))
    expect(sha256Hex(new Uint8Array([0xff, 0x00]))).toBe(
      createHash('sha256')
        .update(new Uint8Array([0xff, 0x00]))
        .digest('hex'),
    )
  })
})
