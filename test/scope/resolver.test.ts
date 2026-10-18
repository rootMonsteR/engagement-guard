import dns from 'node:dns'
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest'
import { parseIp } from '../../src/scope/ip.js'
import { createResolver, type LookupFn } from '../../src/scope/resolver.js'

const ip = (s: string) => {
  const a = parseIp(s)
  if (a === undefined) throw new Error(`bad ip ${s}`)
  return a
}

type Answer = { address: string; family: 4 | 6 }

/** A fake `LookupFn` over a fixed map; unknown names reject like ENOTFOUND. */
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

// Real DNS must never be reached from a unit test: the default lookup is replaced by one that throws.
let realDns: MockInstance
let defaultPathExpected = false
beforeEach(() => {
  defaultPathExpected = false
  realDns = vi.spyOn(dns.promises, 'lookup').mockImplementation(() => {
    throw new Error('real DNS lookup attempted in a unit test')
  })
})
afterEach(() => {
  if (!defaultPathExpected) expect(realDns).not.toHaveBeenCalled()
  vi.restoreAllMocks()
})

describe('createResolver', () => {
  it('resolves through the injected lookup and parses every address', async () => {
    const { lookup, calls } = fakeLookup({
      'www.acme.example': [
        { address: '192.0.2.20', family: 4 },
        { address: '2001:db8:ac::20', family: 6 },
      ],
    })
    const r = createResolver({ lookup })
    expect(await r.resolve('www.acme.example')).toEqual({
      ok: true,
      ips: [ip('192.0.2.20'), ip('2001:db8:ac::20')],
    })
    expect(calls).toEqual(['www.acme.example'])
  })

  it('normalises IPv4-mapped answers, drops duplicates and strips zone ids', async () => {
    const { lookup } = fakeLookup({
      'a.example': [
        { address: '::ffff:192.0.2.20', family: 6 },
        { address: '192.0.2.20', family: 4 },
        { address: 'fe80::1%eth0', family: 6 },
      ],
    })
    const r = createResolver({ lookup })
    expect(await r.resolve('a.example')).toEqual({
      ok: true,
      ips: [ip('192.0.2.20'), ip('fe80::1')],
    })
  })

  it('reports a failed lookup as an error result, never a throw', async () => {
    const { lookup } = fakeLookup({ 'ghost.example': new Error('getaddrinfo ENOTFOUND') })
    const r = createResolver({ lookup })
    const res = await r.resolve('ghost.example')
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.error).toContain('ENOTFOUND')
  })

  it('fails closed on an empty answer or an address it cannot parse', async () => {
    const { lookup } = fakeLookup({
      'empty.example': [],
      'garbage.example': [
        { address: '192.0.2.1', family: 4 },
        { address: 'not-an-ip', family: 4 },
      ],
    })
    const r = createResolver({ lookup })
    expect((await r.resolve('empty.example')).ok).toBe(false)
    expect((await r.resolve('garbage.example')).ok).toBe(false)
  })

  it('refuses a value that is not a hostname without calling lookup', async () => {
    const { lookup, calls } = fakeLookup({})
    const r = createResolver({ lookup })
    expect((await r.resolve('bad host/x')).ok).toBe(false)
    expect(calls).toEqual([])
  })

  it('caches by normalised name until ttlMs has passed on the injected clock', async () => {
    let t = 1_000
    const { lookup, calls } = fakeLookup({
      'www.acme.example': [{ address: '192.0.2.20', family: 4 }],
    })
    const r = createResolver({ lookup, ttlMs: 60_000, now: () => t })
    await r.resolve('www.acme.example')
    t += 59_999
    await r.resolve('WWW.acme.example.')
    expect(calls).toHaveLength(1)
    t += 1
    await r.resolve('www.acme.example')
    expect(calls).toHaveLength(2)
  })

  it('never caches longer than 10 minutes, whatever ttlMs says', async () => {
    let t = 0
    const { lookup, calls } = fakeLookup({ 'a.example': [{ address: '192.0.2.1', family: 4 }] })
    const r = createResolver({ lookup, ttlMs: 3_600_000, now: () => t })
    await r.resolve('a.example')
    t = 600_000
    await r.resolve('a.example')
    expect(calls).toHaveLength(2)
  })

  it('does not cache failures', async () => {
    let fail = true
    const calls: string[] = []
    const lookup: LookupFn = async (host) => {
      calls.push(host)
      if (fail) throw new Error('SERVFAIL')
      return [{ address: '192.0.2.1', family: 4 }]
    }
    const r = createResolver({ lookup, now: () => 0 })
    expect((await r.resolve('a.example')).ok).toBe(false)
    fail = false
    expect((await r.resolve('a.example')).ok).toBe(true)
    expect(calls).toHaveLength(2)
  })

  it('deduplicates concurrent resolves of the same name into one lookup', async () => {
    let release: (v: Answer[]) => void = () => {}
    const calls: string[] = []
    const lookup: LookupFn = (host) => {
      calls.push(host)
      return new Promise((resolve) => {
        release = resolve
      })
    }
    const r = createResolver({ lookup })
    const a = r.resolve('www.acme.example')
    const b = r.resolve('www.acme.example')
    release([{ address: '192.0.2.20', family: 4 }])
    const [ra, rb] = await Promise.all([a, b])
    expect(calls).toEqual(['www.acme.example'])
    expect(ra).toEqual(rb)
    expect(ra.ok).toBe(true)
  })

  it('keeps a forward-confirmed derived-IP set that expires with the cache', async () => {
    let t = 0
    const { lookup } = fakeLookup({ 'www.acme.example': [{ address: '192.0.2.20', family: 4 }] })
    const r = createResolver({ lookup, ttlMs: 60_000, now: () => t })
    const res = await r.resolve('www.acme.example')
    if (!res.ok) throw new Error('expected ok')
    t = 10_000
    r.recordDerived('www.acme.example', res.ips)
    expect(r.derivedFrom(ip('192.0.2.20'))).toBe('www.acme.example')
    expect(r.derivedFrom(ip('::ffff:192.0.2.20'))).toBe('www.acme.example')
    const handBuiltMapped = { family: 6 as const, value: (0xffffn << 32n) | ip('192.0.2.20').value }
    expect(r.derivedFrom(handBuiltMapped)).toBe('www.acme.example')
    expect(r.derivedFrom(ip('192.0.2.21'))).toBeUndefined()
    t = 59_999
    expect(r.derivedFrom(ip('192.0.2.20'))).toBe('www.acme.example')
    // Expires with the resolution that proved it (t = 0 + 60 s), not 60 s after recordDerived.
    t = 60_000
    expect(r.derivedFrom(ip('192.0.2.20'))).toBeUndefined()
  })

  it('gives up on a lookup that never settles after timeoutMs, and later calls retry', async () => {
    const calls: string[] = []
    const lookup: LookupFn = (host) => {
      calls.push(host)
      return new Promise(() => {})
    }
    const r = createResolver({ lookup, timeoutMs: 20 })
    const [a, b] = await Promise.all([r.resolve('hung.example'), r.resolve('hung.example')])
    expect(a).toEqual({ ok: false, error: 'lookup of hung.example timed out after 20 ms' })
    expect(b).toEqual(a)
    expect(calls).toEqual(['hung.example'])
    expect((await r.resolve('hung.example')).ok).toBe(false)
    expect(calls).toEqual(['hung.example', 'hung.example'])
  })

  it('defaults the lookup timeout to 5 s', async () => {
    vi.useFakeTimers()
    try {
      const r = createResolver({ lookup: () => new Promise(() => {}) })
      let settled: unknown
      const p = r.resolve('hung.example').then((res) => {
        settled = res
      })
      await vi.advanceTimersByTimeAsync(4_999)
      expect(settled).toBeUndefined()
      await vi.advanceTimersByTimeAsync(1)
      await p
      expect(settled).toMatchObject({ ok: false })
    } finally {
      vi.useRealTimers()
    }
  })

  it('bounds the cache: inserting past maxEntries evicts the oldest entry', async () => {
    const { lookup, calls } = fakeLookup({
      'a.example': [{ address: '192.0.2.1', family: 4 }],
      'b.example': [{ address: '192.0.2.2', family: 4 }],
      'c.example': [{ address: '192.0.2.3', family: 4 }],
    })
    const r = createResolver({ lookup, now: () => 0, maxEntries: 2 })
    await r.resolve('a.example')
    await r.resolve('b.example')
    await r.resolve('c.example')
    await r.resolve('c.example')
    await r.resolve('b.example')
    expect(calls).toEqual(['a.example', 'b.example', 'c.example'])
    await r.resolve('a.example')
    expect(calls).toEqual(['a.example', 'b.example', 'c.example', 'a.example'])
  })

  it('evicts expired entries before live ones when the cache is full', async () => {
    let t = 0
    const { lookup, calls } = fakeLookup({
      'a.example': [{ address: '192.0.2.1', family: 4 }],
      'b.example': [{ address: '192.0.2.2', family: 4 }],
      'c.example': [{ address: '192.0.2.3', family: 4 }],
    })
    const r = createResolver({ lookup, ttlMs: 1_000, now: () => t, maxEntries: 2 })
    await r.resolve('a.example')
    t = 500
    await r.resolve('b.example')
    t = 1_200 // a has expired, b has not
    await r.resolve('c.example')
    await r.resolve('b.example')
    expect(calls).toEqual(['a.example', 'b.example', 'c.example'])
  })

  it('bounds the derived-IP set the same way', () => {
    const r = createResolver({ lookup: async () => [], now: () => 0, maxEntries: 2 })
    r.recordDerived('a.example', [ip('192.0.2.1')])
    r.recordDerived('b.example', [ip('192.0.2.2')])
    r.recordDerived('c.example', [ip('192.0.2.3')])
    expect(r.derivedFrom(ip('192.0.2.1'))).toBeUndefined()
    expect(r.derivedFrom(ip('192.0.2.2'))).toBe('b.example')
    expect(r.derivedFrom(ip('192.0.2.3'))).toBe('c.example')
  })

  it('uses dns.promises.lookup when no lookup is injected (here a throwing stub)', async () => {
    defaultPathExpected = true
    const r = createResolver()
    const res = await r.resolve('www.acme.example')
    expect(res.ok).toBe(false)
    if (!res.ok) expect(res.error).toContain('real DNS lookup attempted')
    expect(realDns).toHaveBeenCalledWith('www.acme.example', { all: true })
  })
})
