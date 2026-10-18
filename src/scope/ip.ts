// IPv4/IPv6 addresses as bigint, CIDR and range arithmetic, and address classification.
// Pure arithmetic: no I/O, no dependencies. Parsers are strict and return `undefined` on any
// malformed input (no trimming, no shorthand, no zone ids); callers normalise whitespace first.

export type IpFamily = 4 | 6

/** An address. `::ffff:a.b.c.d` (IPv4-mapped IPv6) is normalised to family 4. */
export interface IpAddr {
  family: IpFamily
  value: bigint
}

/** An inclusive address range within one family. */
export interface IpRange {
  family: IpFamily
  start: bigint
  end: bigint
}

export type IpClass =
  | 'loopback'
  | 'private'
  | 'link-local'
  | 'cgnat'
  | 'multicast'
  | 'unspecified'
  | 'documentation'
  | 'reserved'
  | 'public'

const MAX_V4 = (1n << 32n) - 1n
const MAX_V6 = (1n << 128n) - 1n
const MAPPED_TAG = 0xffffn // ::ffff:0:0/96 is value >> 32 === 0xffff
const NAT64_TAG = 0x64_ff9b_0000_0000_0000_0000n // 64:ff9b::/96 is value >> 32 === NAT64_TAG

const DEC_OCTET = /^(0|[1-9][0-9]{0,2})$/
const HEX_GROUP = /^[0-9a-fA-F]{1,4}$/
const PREFIX_LEN = /^(0|[1-9][0-9]{0,2})$/

function bitsOf(family: IpFamily): number {
  return family === 4 ? 32 : 128
}

function maxOf(family: IpFamily): bigint {
  return family === 4 ? MAX_V4 : MAX_V6
}

function parseDecOctet(s: string): number | undefined {
  if (!DEC_OCTET.test(s)) return undefined
  const n = Number(s)
  return n <= 255 ? n : undefined
}

function parseV4(s: string): bigint | undefined {
  const parts = s.split('.')
  if (parts.length !== 4) return undefined
  let value = 0n
  for (const part of parts) {
    const octet = parseDecOctet(part)
    if (octet === undefined) return undefined
    value = (value << 8n) | BigInt(octet)
  }
  return value
}

function parseHexGroups(part: string): bigint[] | undefined {
  if (part === '') return []
  const groups: bigint[] = []
  for (const g of part.split(':')) {
    if (!HEX_GROUP.test(g)) return undefined
    groups.push(BigInt(`0x${g}`))
  }
  return groups
}

function parseV6(s: string): bigint | undefined {
  // Anything outside hex digits, ':' and '.' (zone ids, brackets, whitespace, signs) is rejected.
  if (!/^[0-9a-fA-F:.]+$/.test(s)) return undefined

  // An embedded IPv4 address may only appear as the final 32 bits.
  let head = s
  let tail: bigint[] = []
  const lastColon = s.lastIndexOf(':')
  const lastToken = s.slice(lastColon + 1)
  if (lastToken.includes('.')) {
    const v4 = parseV4(lastToken)
    if (v4 === undefined) return undefined
    tail = [v4 >> 16n, v4 & 0xffffn]
    head = s.slice(0, lastColon + 1)
    if (!head.endsWith('::')) head = head.slice(0, -1)
  }

  const halves = head.split('::')
  if (halves.length > 2) return undefined
  const left = parseHexGroups(halves[0] ?? '')
  if (left === undefined) return undefined

  let groups: bigint[]
  if (halves.length === 2) {
    const right = parseHexGroups(halves[1] ?? '')
    if (right === undefined) return undefined
    const present = left.length + right.length + tail.length
    if (present > 7) return undefined
    groups = [...left, ...new Array<bigint>(8 - present).fill(0n), ...right, ...tail]
  } else {
    groups = [...left, ...tail]
    if (groups.length !== 8) return undefined
  }

  let value = 0n
  for (const g of groups) value = (value << 16n) | g
  return value
}

/** Parse a single IPv4 (strict dotted quad) or IPv6 address. */
export function parseIp(s: string): IpAddr | undefined {
  if (s.includes(':')) {
    const value = parseV6(s)
    if (value === undefined) return undefined
    if (value >> 32n === MAPPED_TAG) return { family: 4, value: value & MAX_V4 }
    return { family: 6, value }
  }
  const value = parseV4(s)
  return value === undefined ? undefined : { family: 4, value }
}

function blockOf(family: IpFamily, value: bigint, prefix: number): IpRange {
  const hostMask = (1n << BigInt(bitsOf(family) - prefix)) - 1n
  const start = value & ~hostMask
  return { family, start, end: start | hostMask }
}

/** Parse `addr/len` (host bits allowed and cleared) or a bare address (/32 or /128). */
export function parseCidr(s: string): IpRange | undefined {
  const slash = s.indexOf('/')
  if (slash < 0) {
    const addr = parseIp(s)
    return addr === undefined
      ? undefined
      : { family: addr.family, start: addr.value, end: addr.value }
  }
  const addrText = s.slice(0, slash)
  const lenText = s.slice(slash + 1)
  if (!PREFIX_LEN.test(lenText)) return undefined
  const addr = parseIp(addrText)
  if (addr === undefined) return undefined
  let prefix = Number(lenText)
  if (addr.family === 4 && addrText.includes(':')) {
    // IPv4-mapped address written with an IPv6 prefix length.
    if (prefix < 96) return undefined
    prefix -= 96
  }
  if (prefix > bitsOf(addr.family)) return undefined
  return blockOf(addr.family, addr.value, prefix)
}

function parseOctetRange(s: string): IpRange | undefined {
  if (!s.includes('-') && !s.includes('*')) return undefined
  const parts = s.split('.')
  if (parts.length !== 4) return undefined
  const lo: number[] = []
  const hi: number[] = []
  for (const part of parts) {
    if (part === '*') {
      lo.push(0)
      hi.push(255)
      continue
    }
    const bounds = part.split('-')
    if (bounds.length > 2) return undefined
    const a = parseDecOctet(bounds[0] ?? '')
    const b = parseDecOctet(bounds[bounds.length - 1] ?? '')
    if (a === undefined || b === undefined || a > b) return undefined
    lo.push(a)
    hi.push(b)
  }
  // The set is one contiguous range only if every octet after the first varying one is full.
  const firstVarying = lo.findIndex((v, i) => v !== hi[i])
  if (firstVarying >= 0) {
    for (let i = firstVarying + 1; i < 4; i++) {
      if (lo[i] !== 0 || hi[i] !== 255) return undefined
    }
  }
  let start = 0n
  let end = 0n
  for (let i = 0; i < 4; i++) {
    start = (start << 8n) | BigInt(lo[i] ?? 0)
    end = (end << 8n) | BigInt(hi[i] ?? 0)
  }
  return { family: 4, start, end }
}

/** Parse `a-b` (two full addresses, same family) or an nmap-style IPv4 octet range. */
export function parseIpRange(s: string): IpRange | undefined {
  const sides = s.split('-')
  if (sides.length === 2) {
    const a = parseIp(sides[0] ?? '')
    const b = parseIp(sides[1] ?? '')
    if (a !== undefined && b !== undefined) {
      if (a.family !== b.family || a.value > b.value) return undefined
      return { family: a.family, start: a.value, end: b.value }
    }
  }
  return parseOctetRange(s)
}

/** Parse a CIDR block, an address range or a single address. */
export function parseIpSpec(s: string): IpRange | undefined {
  return parseCidr(s) ?? parseIpRange(s)
}

function formatV4(value: bigint): string {
  return [24n, 16n, 8n, 0n].map((shift) => String((value >> shift) & 0xffn)).join('.')
}

/** Dotted quad for IPv4; RFC 5952 canonical (lowercase, compressed) text for IPv6. */
export function formatIp(ip: IpAddr): string {
  if (ip.value < 0n || ip.value > maxOf(ip.family)) {
    throw new RangeError(`address value out of range for IPv${ip.family}`)
  }
  if (ip.family === 4) return formatV4(ip.value)
  if (ip.value >> 32n === MAPPED_TAG) return `::ffff:${formatV4(ip.value & MAX_V4)}`

  const groups: bigint[] = []
  for (let shift = 112n; shift >= 0n; shift -= 16n) groups.push((ip.value >> shift) & 0xffffn)

  // Longest run of two or more zero groups; the first one wins a tie.
  let bestStart = -1
  let bestLen = 1
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0n) {
      i++
      continue
    }
    let j = i
    while (j < 8 && groups[j] === 0n) j++
    if (j - i > bestLen) {
      bestStart = i
      bestLen = j - i
    }
    i = j
  }

  const hex = (gs: bigint[]): string => gs.map((g) => g.toString(16)).join(':')
  if (bestStart < 0) return hex(groups)
  return `${hex(groups.slice(0, bestStart))}::${hex(groups.slice(bestStart + bestLen))}`
}

function isValidRange(r: IpRange): boolean {
  return (
    (r.family === 4 || r.family === 6) &&
    r.start >= 0n &&
    r.start <= r.end &&
    r.end <= maxOf(r.family)
  )
}

/** CIDR notation when the range is an aligned power-of-two block, otherwise `start-end`. */
export function formatRange(r: IpRange): string {
  if (!isValidRange(r)) throw new RangeError('invalid IP range')
  const size = r.end - r.start + 1n
  if ((size & (size - 1n)) === 0n && r.start % size === 0n) {
    const hostBits = size.toString(2).length - 1
    return `${formatIp({ family: r.family, value: r.start })}/${bitsOf(r.family) - hostBits}`
  }
  return `${formatIp({ family: r.family, value: r.start })}-${formatIp({ family: r.family, value: r.end })}`
}

/** True when `inner` lies entirely inside `outer` (same family, both well-formed). */
export function rangeContains(outer: IpRange, inner: IpRange): boolean {
  return (
    isValidRange(outer) &&
    isValidRange(inner) &&
    outer.family === inner.family &&
    outer.start <= inner.start &&
    inner.end <= outer.end
  )
}

/** True when the ranges share at least one address (same family, both well-formed). */
export function rangesIntersect(a: IpRange, b: IpRange): boolean {
  return (
    isValidRange(a) &&
    isValidRange(b) &&
    a.family === b.family &&
    a.start <= b.end &&
    b.start <= a.end
  )
}

/** Well-formed ranges of `family`, sorted, with overlapping and adjacent ranges merged. */
function mergeRanges(family: IpFamily, ranges: IpRange[]): IpRange[] {
  const sorted = ranges
    .filter((r) => r.family === family && isValidRange(r))
    .sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0))
  const merged: IpRange[] = []
  for (const r of sorted) {
    const last = merged[merged.length - 1]
    if (last !== undefined && r.start <= last.end + 1n) {
      if (r.end > last.end) last.end = r.end
    } else {
      merged.push({ family, start: r.start, end: r.end })
    }
  }
  return merged
}

/** The parts of `r` not in any of `minus`, sorted and non-overlapping. */
export function subtractRanges(r: IpRange, minus: IpRange[]): IpRange[] {
  if (!isValidRange(r)) return []
  const out: IpRange[] = []
  let cursor = r.start
  for (const m of mergeRanges(r.family, minus)) {
    if (m.end < cursor) continue
    if (m.start > r.end) break
    if (m.start > cursor) out.push({ family: r.family, start: cursor, end: m.start - 1n })
    cursor = m.end + 1n
    if (cursor > r.end) return out
  }
  out.push({ family: r.family, start: cursor, end: r.end })
  return out
}

/** True when every address of `r` lies in the union of `cover` (adjacent ranges are merged). */
export function coveredBy(r: IpRange, cover: IpRange[]): boolean {
  if (!isValidRange(r)) return false
  return mergeRanges(r.family, cover).some((m) => m.start <= r.start && r.end <= m.end)
}

function mustCidr(s: string): IpRange {
  const r = parseCidr(s)
  if (r === undefined) throw new Error(`invalid built-in CIDR: ${s}`)
  return r
}

function table(entries: [string, IpClass][]): [IpRange, IpClass][] {
  return entries.map(([cidr, cls]) => [mustCidr(cidr), cls])
}

// First match wins, so more specific blocks come before the blocks that contain them.
const V4_CLASSES = table([
  ['0.0.0.0/32', 'unspecified'],
  ['0.0.0.0/8', 'reserved'],
  ['127.0.0.0/8', 'loopback'],
  ['10.0.0.0/8', 'private'],
  ['172.16.0.0/12', 'private'],
  ['192.168.0.0/16', 'private'],
  ['100.64.0.0/10', 'cgnat'],
  ['169.254.0.0/16', 'link-local'],
  ['192.0.2.0/24', 'documentation'],
  ['198.51.100.0/24', 'documentation'],
  ['203.0.113.0/24', 'documentation'],
  ['192.0.0.0/24', 'reserved'],
  ['198.18.0.0/15', 'reserved'],
  ['224.0.0.0/4', 'multicast'],
  ['240.0.0.0/4', 'reserved'],
])

const V6_CLASSES = table([
  ['::/128', 'unspecified'],
  ['::1/128', 'loopback'],
  ['::/8', 'reserved'],
  ['100::/64', 'reserved'],
  ['fc00::/7', 'private'],
  ['fe80::/10', 'link-local'],
  ['fec0::/10', 'reserved'],
  ['ff00::/8', 'multicast'],
  ['2001:db8::/32', 'documentation'],
  ['3fff::/20', 'documentation'],
  ['2000::/3', 'public'],
])

/** IPv6 blocks whose low 32 bits are an IPv4 address: IPv4-mapped and NAT64 (RFC 6052). */
const V4_EMBEDDING_TAGS: readonly bigint[] = [MAPPED_TAG, NAT64_TAG]

function embeddingBlock(tag: bigint): IpRange {
  return { family: 6, start: tag << 32n, end: (tag << 32n) | MAX_V4 }
}

/** A structurally valid address: a known family and a bigint value within that family. */
function isValidAddr(ip: IpAddr): boolean {
  return (
    typeof ip === 'object' &&
    ip !== null &&
    (ip.family === 4 || ip.family === 6) &&
    typeof ip.value === 'bigint' &&
    ip.value >= 0n &&
    ip.value <= maxOf(ip.family)
  )
}

/**
 * For a family-4 range, the same addresses as embedded in each IPv6 block that carries IPv4
 * (`::ffff:0:0/96` IPv4-mapped, `64:ff9b::/96` NAT64). Empty for any other range.
 */
export function ipv6Embeddings(r: IpRange): IpRange[] {
  if (r.family !== 4 || !isValidRange(r)) return []
  return V4_EMBEDDING_TAGS.map((tag) => ({
    family: 6,
    start: (tag << 32n) | r.start,
    end: (tag << 32n) | r.end,
  }))
}

/**
 * Classify an address. A family-6 value in `::ffff:0:0/96` (IPv4-mapped) or `64:ff9b::/96` (NAT64)
 * is classified by the IPv4 address it embeds. Fails closed: a malformed address (unknown family,
 * non-bigint or out-of-range value) is `'reserved'`, never `'public'`.
 */
export function classifyIp(ip: IpAddr): IpClass {
  if (!isValidAddr(ip)) return 'reserved'
  let family = ip.family
  let value = ip.value
  if (family === 6 && V4_EMBEDDING_TAGS.includes(value >> 32n)) {
    family = 4
    value &= MAX_V4
  }
  const point: IpRange = { family, start: value, end: value }
  const entries = family === 4 ? V4_CLASSES : V6_CLASSES
  for (const [range, cls] of entries) {
    if (rangeContains(range, point)) return cls
  }
  return family === 4 ? 'public' : 'reserved'
}

/**
 * Every class `classifyIp` gives to some address in `r` (same first-match tables, so the answer
 * agrees with classifying each address one by one). The `::ffff:0:0/96` and `64:ff9b::/96` parts
 * of a family-6 range are classified by their IPv4 addresses. An invalid range has no classes.
 */
export function classesInRange(r: IpRange): Set<IpClass> {
  const classes = new Set<IpClass>()
  if (!isValidRange(r)) return classes
  let remaining = [r]
  if (r.family === 6) {
    for (const tag of V4_EMBEDDING_TAGS) {
      const block = embeddingBlock(tag)
      if (!rangesIntersect(r, block)) continue
      const start = (r.start > block.start ? r.start : block.start) & MAX_V4
      const end = (r.end < block.end ? r.end : block.end) & MAX_V4
      for (const c of classesInRange({ family: 4, start, end })) classes.add(c)
      remaining = remaining.flatMap((piece) => subtractRanges(piece, [block]))
    }
  }
  for (const [block, cls] of r.family === 4 ? V4_CLASSES : V6_CLASSES) {
    if (remaining.length === 0) break
    if (!remaining.some((piece) => rangesIntersect(piece, block))) continue
    classes.add(cls)
    remaining = remaining.flatMap((piece) => subtractRanges(piece, [block]))
  }
  if (remaining.length > 0) classes.add(r.family === 4 ? 'public' : 'reserved')
  return classes
}

/** Classes treated as "internal" for scope purposes. Documentation ranges count as public. */
export function isPrivateLike(c: IpClass): boolean {
  return c === 'private' || c === 'link-local' || c === 'cgnat' || c === 'loopback'
}
