import type { Engagement } from '../engagement/schema.js'

/**
 * How a tool's rate flag is read: nmap `-T`, packets/s, requests/s, worker threads, parallel hosts,
 * an inter-packet interval (hping3 `-i u1000`, read as packets/s) or a bandwidth in bits/s (zmap
 * `-B 10M`, read as packets/s assuming minimum-size 64-byte frames, which over-estimates the rate).
 */
export type RateKind =
  | 'nmap-timing'
  | 'pps'
  | 'rps'
  | 'threads'
  | 'parallel-hosts'
  | 'interval'
  | 'bandwidth'

export type RateField = 'nmapTiming' | 'pps' | 'rps' | 'threads' | 'parallelHosts'

/**
 * Rate and timing values found in one segment (the largest value per field). `raw` keeps the flags
 * as written; `flags` names the flag that set each value and `kinds` how it was read, so suggestions
 * use the tool's own spelling.
 */
export interface RateFlags {
  nmapTiming?: number
  pps?: number
  rps?: number
  threads?: number
  parallelHosts?: number
  raw: string[]
  flags?: Partial<Record<RateField, string>>
  kinds?: Partial<Record<RateField, RateKind>>
}

export interface RateViolation {
  flag: string
  value: number
  limit: number
  suggestion: string
}

export type RateLimits = Engagement['roe']['rate_limits']

export const RATE_FIELD: Readonly<Record<RateKind, RateField>> = {
  'nmap-timing': 'nmapTiming',
  pps: 'pps',
  rps: 'rps',
  threads: 'threads',
  'parallel-hosts': 'parallelHosts',
  interval: 'pps',
  bandwidth: 'pps',
}

/** nmap timing template names (`-T paranoid|sneaky|polite|normal|aggressive|insane`). */
const NMAP_TIMING_NAMES: ReadonlyMap<string, number> = new Map([
  ['paranoid', 0],
  ['sneaky', 1],
  ['polite', 2],
  ['normal', 3],
  ['aggressive', 4],
  ['insane', 5],
])

const UNIT_SECONDS: Readonly<Record<string, number>> = { s: 1, m: 60, h: 3600, d: 86400 }
const NUMBER = String.raw`\d+(?:\.\d+)?(?:e[+-]?\d+)?`
// `100`, `0.5`, `1e6` and curl's `--rate` forms `N/s`, `N/m`, `N/3h`.
const RATE_VALUE = new RegExp(`^(${NUMBER})(?:/(\\d*)([smhd]))?$`, 'i')
// hping3 `-i X` (seconds) or `-i uX` (microseconds).
const INTERVAL_VALUE = new RegExp(`^(u?)(${NUMBER})$`, 'i')
// zmap `-B` bits/second with optional K, M or G suffix.
const BANDWIDTH_VALUE = new RegExp(`^(${NUMBER})([kmg]?)$`, 'i')
const BANDWIDTH_MULTIPLIER: Readonly<Record<string, number>> = { '': 1, k: 1e3, m: 1e6, g: 1e9 }
/** Bits in a minimum Ethernet frame; dividing a bandwidth by it gives the highest packet rate. */
export const MIN_FRAME_BITS = 512

/** Parses a rate flag's value, or `undefined` when it is not a value of that kind. */
export function parseRateValue(kind: RateKind, value: string): number | undefined {
  const v = value.trim()
  if (kind === 'nmap-timing') {
    if (/^[0-5]$/.test(v)) return Number(v)
    return NMAP_TIMING_NAMES.get(v.toLowerCase())
  }
  if (kind === 'interval') {
    const m = INTERVAL_VALUE.exec(v)
    if (!m) return undefined
    const seconds = Number(m[2]) / (m[1] ? 1e6 : 1)
    return seconds === 0 ? Number.POSITIVE_INFINITY : 1 / seconds
  }
  if (kind === 'bandwidth') {
    const m = BANDWIDTH_VALUE.exec(v)
    if (!m) return undefined
    return (Number(m[1]) * (BANDWIDTH_MULTIPLIER[(m[2] ?? '').toLowerCase()] ?? 1)) / MIN_FRAME_BITS
  }
  const m = RATE_VALUE.exec(v)
  if (!m) return undefined
  const n = Number(m[1])
  if (!Number.isFinite(n)) return undefined
  if (m[3] === undefined) return n
  const per = (m[2] ? Number(m[2]) : 1) * (UNIT_SECONDS[m[3].toLowerCase()] ?? 1)
  return per > 0 ? n / per : undefined
}

/** Records one rate flag in `r`, keeping the largest value per field. Returns false when unparsable. */
export function addRate(r: RateFlags, kind: RateKind, flag: string, value: string): boolean {
  const n = parseRateValue(kind, value)
  if (n === undefined) return false
  const field = RATE_FIELD[kind]
  r.raw.push(kind === 'nmap-timing' && flag === '-T' ? `-T${value}` : `${flag} ${value}`)
  const current = r[field]
  if (current === undefined || n > current) {
    r[field] = n
    r.flags = { ...r.flags, [field]: flag }
    r.kinds = { ...r.kinds, [field]: kind }
  }
  return true
}

const DEFAULT_FLAG: Readonly<Record<RateField, string>> = {
  nmapTiming: '-T',
  pps: '--max-rate',
  rps: '-rl',
  threads: '-t',
  parallelHosts: '--max-hostgroup',
}

function suggest(
  field: RateField,
  flag: string,
  kind: RateKind | undefined,
  limit: number,
): string {
  if (field === 'nmapTiming' && flag === '-T') return `-T${limit}`
  if (kind === 'interval') return `-i u${Math.ceil(1e6 / limit)}`
  if (kind === 'bandwidth') return `${flag} ${limit * MIN_FRAME_BITS}`
  return `${flag} ${limit}`
}

/**
 * Compares rate flags with the case's `rate_limits`: nmap timing against `nmap_max_timing`, pps
 * against `pps`, rps against `rps`, worker threads against `rps` (conservative: each thread may
 * send at least one request per second), parallel hosts against `max_parallel_hosts`.
 */
export function checkRate(r: RateFlags, limits: RateLimits): RateViolation[] {
  const out: RateViolation[] = []
  const check = (field: RateField, limit: number) => {
    const value = r[field]
    if (value === undefined || value <= limit) return
    const flag = r.flags?.[field] ?? DEFAULT_FLAG[field]
    out.push({ flag, value, limit, suggestion: suggest(field, flag, r.kinds?.[field], limit) })
  }
  check('nmapTiming', limits.nmap_max_timing)
  check('pps', limits.pps)
  check('rps', limits.rps)
  check('threads', limits.rps)
  check('parallelHosts', limits.max_parallel_hosts)
  return out
}
