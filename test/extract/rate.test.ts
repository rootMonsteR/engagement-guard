import { describe, expect, it } from 'vitest'
import { checkRate, parseRateValue, type RateFlags } from '../../src/extract/rate.js'

const limits = { rps: 50, pps: 1000, nmap_max_timing: 3, max_parallel_hosts: 16 }

describe('parseRateValue', () => {
  it('reads nmap timing numbers and names', () => {
    expect(parseRateValue('nmap-timing', '4')).toBe(4)
    expect(parseRateValue('nmap-timing', 'aggressive')).toBe(4)
    expect(parseRateValue('nmap-timing', 'Paranoid')).toBe(0)
    expect(parseRateValue('nmap-timing', 'insane')).toBe(5)
    expect(parseRateValue('nmap-timing', '9')).toBeUndefined()
  })

  it('reads plain numbers and curl-style per-unit rates', () => {
    expect(parseRateValue('pps', '100000')).toBe(100000)
    expect(parseRateValue('pps', '0.5')).toBe(0.5)
    expect(parseRateValue('rps', '120/m')).toBe(2)
    expect(parseRateValue('rps', '10/s')).toBe(10)
    expect(parseRateValue('rps', 'fast')).toBeUndefined()
  })
})

describe('checkRate', () => {
  it('suggests -T3 for -T4 when the RoE allows 3', () => {
    const r: RateFlags = { nmapTiming: 4, raw: ['-T4'], flags: { nmapTiming: '-T' } }
    expect(checkRate(r, limits)).toEqual([{ flag: '-T', value: 4, limit: 3, suggestion: '-T3' }])
  })

  it('treats -T aggressive as 4', () => {
    const t = parseRateValue('nmap-timing', 'aggressive')
    const r: RateFlags = { ...(t === undefined ? {} : { nmapTiming: t }), raw: ['-T aggressive'] }
    expect(checkRate(r, limits)[0]).toMatchObject({ value: 4, suggestion: '-T3' })
  })

  it('caps masscan --rate at pps', () => {
    const r: RateFlags = { pps: 100000, raw: ['--rate 100000'], flags: { pps: '--rate' } }
    expect(checkRate(r, limits)).toEqual([
      { flag: '--rate', value: 100000, limit: 1000, suggestion: '--rate 1000' },
    ])
  })

  it('caps nuclei -rl at rps and ffuf -t threads at rps', () => {
    const nuclei = checkRate({ rps: 500, raw: ['-rl 500'], flags: { rps: '-rl' } }, limits)
    expect(nuclei[0]?.suggestion).toBe('-rl 50')
    const ffuf = checkRate({ threads: 200, raw: ['-t 200'], flags: { threads: '-t' } }, limits)
    expect(ffuf[0]?.suggestion).toBe('-t 50')
  })

  it('caps parallel hosts and accepts compliant values', () => {
    const r: RateFlags = { parallelHosts: 64, raw: ['-bs 64'], flags: { parallelHosts: '-bs' } }
    expect(checkRate(r, limits)[0]).toMatchObject({ limit: 16, suggestion: '-bs 16' })
    const ok: RateFlags = {
      nmapTiming: 3,
      pps: 1000,
      rps: 50,
      threads: 10,
      parallelHosts: 16,
      raw: [],
    }
    expect(checkRate(ok, limits)).toEqual([])
  })

  it('falls back to default flag names', () => {
    expect(checkRate({ nmapTiming: 5, raw: [] }, limits)[0]?.flag).toBe('-T')
  })
})

describe('interval and bandwidth rates', () => {
  it('reads hping3 intervals and zmap bandwidths as packets per second', () => {
    expect(parseRateValue('interval', 'u1000')).toBe(1000)
    expect(parseRateValue('interval', '2')).toBe(0.5)
    expect(parseRateValue('interval', 'u0')).toBe(Number.POSITIVE_INFINITY)
    expect(parseRateValue('bandwidth', '1M')).toBe(1e6 / 512)
    expect(parseRateValue('bandwidth', 'fast')).toBeUndefined()
    expect(parseRateValue('pps', '1.5e3')).toBe(1500)
  })

  it('suggests a compliant interval or bandwidth', () => {
    const interval: RateFlags = {
      pps: 10000,
      raw: ['-i u100'],
      flags: { pps: '-i' },
      kinds: { pps: 'interval' },
    }
    expect(checkRate(interval, limits)[0]?.suggestion).toBe('-i u1000')
    const bw: RateFlags = {
      pps: 19531,
      raw: ['-B 10M'],
      flags: { pps: '-B' },
      kinds: { pps: 'bandwidth' },
    }
    expect(checkRate(bw, limits)[0]?.suggestion).toBe('-B 512000')
  })
})
