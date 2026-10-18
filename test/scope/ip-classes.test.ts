import { describe, expect, it } from 'vitest'
import { classesInRange, classifyIp, type IpRange, parseIpSpec } from '../../src/scope/ip.js'

const classes = (spec: string) => {
  const r = parseIpSpec(spec)
  if (r === undefined) throw new Error(`bad spec ${spec}`)
  return [...classesInRange(r)].sort()
}

describe('classesInRange', () => {
  it('agrees with classifyIp for a single address', () => {
    for (const ip of ['192.0.2.10', '10.1.2.3', '127.0.0.1', '8.8.8.8', 'fd00::1', '2001:db8::1']) {
      const r = parseIpSpec(ip) as IpRange
      expect([...classesInRange(r)]).toEqual([classifyIp({ family: r.family, value: r.start })])
    }
  })

  it('finds every class inside a broad range, including the fallback', () => {
    const all = classes('0.0.0.0/0')
    expect(all).toEqual(
      expect.arrayContaining(['private', 'loopback', 'cgnat', 'link-local', 'public', 'reserved']),
    )
    expect(classes('192.0.2.0/24')).toEqual(['documentation'])
    expect(classes('192.168.0.0/15')).toEqual(['private', 'public'])
  })

  it('respects first-match shadowing', () => {
    // 0.0.0.0/32 is unspecified and the rest of 0.0.0.0/8 is reserved.
    expect(classes('0.0.0.0/31')).toEqual(['reserved', 'unspecified'])
    expect(classes('0.0.0.0')).toEqual(['unspecified'])
  })

  it('classifies the IPv4-mapped part of an IPv6 range by its IPv4 addresses', () => {
    const r: IpRange = { family: 6, start: 0xffff_0a00_0000n, end: 0xffff_0a00_00ffn }
    expect([...classesInRange(r)]).toEqual(['private'])
    expect(classes('::/0')).toEqual(expect.arrayContaining(['private', 'loopback', 'cgnat']))
  })

  it('classifies the NAT64 part of an IPv6 range by its embedded IPv4 addresses', () => {
    expect(classes('64:ff9b::7f00:0/120')).toEqual(['loopback'])
    expect(classes('64:ff9b::a00:0/104')).toEqual(['private'])
    expect(classes('64:ff9b::/96')).toEqual(
      expect.arrayContaining(['private', 'loopback', 'public', 'documentation']),
    )
    for (const ip of ['64:ff9b::7f00:1', '64:ff9b::a00:5', '64:ff9b::808:808']) {
      const r = parseIpSpec(ip) as IpRange
      expect([...classesInRange(r)]).toEqual([classifyIp({ family: r.family, value: r.start })])
    }
  })

  it('returns nothing for an invalid range', () => {
    expect(classesInRange({ family: 4, start: 5n, end: 1n }).size).toBe(0)
  })
})
