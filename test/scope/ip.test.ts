import { describe, expect, it } from 'vitest'
import {
  classifyIp,
  coveredBy,
  formatIp,
  formatRange,
  type IpAddr,
  type IpClass,
  type IpRange,
  ipv6Embeddings,
  isPrivateLike,
  parseCidr,
  parseIp,
  parseIpRange,
  parseIpSpec,
  rangeContains,
  rangesIntersect,
  subtractRanges,
} from '../../src/scope/ip.js'

// Independent of the module under test: dotted quad -> bigint.
function q(a: number, b: number, c: number, d: number): bigint {
  return BigInt(((a * 256 + b) * 256 + c) * 256 + d)
}

function v4(a: number, b: number, c: number, d: number): IpAddr {
  return { family: 4, value: q(a, b, c, d) }
}

function r4(start: bigint, end: bigint): IpRange {
  return { family: 4, start, end }
}

function ip(s: string): IpAddr {
  const parsed = parseIp(s)
  if (parsed === undefined) throw new Error(`test fixture failed to parse: ${s}`)
  return parsed
}

function spec(s: string): IpRange {
  const parsed = parseIpSpec(s)
  if (parsed === undefined) throw new Error(`test fixture failed to parse: ${s}`)
  return parsed
}

const DOC_V6 = 0x2001_0db8n << 96n

type Row = [label: string, actual: () => unknown, expected: unknown]

const rows: Row[] = [
  // --- parseIp: IPv4 ---
  ['parseIp v4 dotted quad', () => parseIp('192.0.2.1'), v4(192, 0, 2, 1)],
  ['parseIp v4 zero', () => parseIp('0.0.0.0'), v4(0, 0, 0, 0)],
  ['parseIp v4 broadcast', () => parseIp('255.255.255.255'), v4(255, 255, 255, 255)],
  ['parseIp rejects octet > 255', () => parseIp('192.0.2.256'), undefined],
  ['parseIp rejects leading-zero octet', () => parseIp('01.2.3.4'), undefined],
  ['parseIp rejects leading-zero last octet', () => parseIp('192.0.2.01'), undefined],
  ['parseIp rejects shorthand 1.2.3', () => parseIp('1.2.3'), undefined],
  ['parseIp rejects shorthand 10.1', () => parseIp('10.1'), undefined],
  ['parseIp rejects five octets', () => parseIp('192.0.2.1.5'), undefined],
  ['parseIp rejects empty octet', () => parseIp('192.0..1'), undefined],
  ['parseIp rejects sign', () => parseIp('192.0.2.+1'), undefined],
  ['parseIp rejects whitespace', () => parseIp(' 192.0.2.1'), undefined],
  ['parseIp rejects empty string', () => parseIp(''), undefined],
  ['parseIp rejects a hostname', () => parseIp('host.example'), undefined],

  // --- parseIp: IPv6 ---
  ['parseIp v6 with ::', () => parseIp('2001:db8::1'), { family: 6, value: DOC_V6 + 1n }],
  [
    'parseIp v6 uppercase hex',
    () => parseIp('2001:DB8::ABCD'),
    { family: 6, value: DOC_V6 + 0xabcdn },
  ],
  [
    'parseIp v6 full form',
    () => parseIp('2001:0db8:0000:0000:0000:0000:0000:0001'),
    { family: 6, value: DOC_V6 + 1n },
  ],
  ['parseIp v6 ::', () => parseIp('::'), { family: 6, value: 0n }],
  ['parseIp v6 ::1', () => parseIp('::1'), { family: 6, value: 1n }],
  ['parseIp v6 trailing ::', () => parseIp('2001:db8::'), { family: 6, value: DOC_V6 }],
  [
    'parseIp v6 :: in the middle',
    () => parseIp('2001:db8:1::2:3'),
    { family: 6, value: DOC_V6 + (1n << 80n) + (2n << 16n) + 3n },
  ],
  ['parseIp ::ffff:a.b.c.d is family 4', () => parseIp('::ffff:192.0.2.66'), v4(192, 0, 2, 66)],
  ['parseIp ::ffff: in hex is family 4', () => parseIp('::ffff:c000:242'), v4(192, 0, 2, 66)],
  [
    'parseIp v6 embedded v4 outside ::ffff:0:0/96 stays v6',
    () => parseIp('64:ff9b::192.0.2.1'),
    { family: 6, value: (0x64n << 112n) + (0xff9bn << 96n) + q(192, 0, 2, 1) },
  ],
  ['parseIp rejects zone id', () => parseIp('fe80::1%eth0'), undefined],
  ['parseIp rejects 5-digit group', () => parseIp('2001:db8::12345'), undefined],
  ['parseIp rejects two ::', () => parseIp('2001::db8::1'), undefined],
  ['parseIp rejects :::', () => parseIp('2001:::1'), undefined],
  ['parseIp rejects 9 groups', () => parseIp('1:2:3:4:5:6:7:8:9'), undefined],
  ['parseIp rejects 7 groups without ::', () => parseIp('1:2:3:4:5:6:7'), undefined],
  ['parseIp rejects 8 groups plus ::', () => parseIp('1:2:3:4::5:6:7:8'), undefined],
  ['parseIp rejects leading single colon', () => parseIp(':1::2'), undefined],
  ['parseIp rejects trailing single colon', () => parseIp('1::2:'), undefined],
  ['parseIp rejects non-hex group', () => parseIp('2001:db8::g'), undefined],
  ['parseIp rejects bad embedded v4', () => parseIp('::ffff:192.0.2.256'), undefined],
  ['parseIp rejects embedded v4 not last', () => parseIp('::192.0.2.1:1'), undefined],
  ['parseIp rejects brackets', () => parseIp('[2001:db8::1]'), undefined],

  // --- formatIp ---
  ['formatIp v4', () => formatIp(v4(192, 0, 2, 1)), '192.0.2.1'],
  ['formatIp v6 compresses', () => formatIp(ip('2001:0DB8:0:0:0:0:0:1')), '2001:db8::1'],
  ['formatIp v6 ::', () => formatIp({ family: 6, value: 0n }), '::'],
  ['formatIp v6 ::1', () => formatIp({ family: 6, value: 1n }), '::1'],
  [
    'formatIp v6 leaves a single zero group alone',
    () => formatIp(ip('2001:db8:0:1:1:1:1:1')),
    '2001:db8:0:1:1:1:1:1',
  ],
  [
    'formatIp v6 compresses the longest zero run',
    () => formatIp(ip('2001:0:0:1:0:0:0:1')),
    '2001:0:0:1::1',
  ],
  [
    'formatIp v6 compresses the first of equal runs',
    () => formatIp(ip('2001:db8:0:0:1:0:0:1')),
    '2001:db8::1:0:0:1',
  ],
  ['formatIp v6 trailing zeros', () => formatIp(ip('2001:db8::')), '2001:db8::'],

  // --- parseCidr ---
  [
    'parseCidr normalises host bits',
    () => parseCidr('192.0.2.77/25'),
    r4(q(192, 0, 2, 0), q(192, 0, 2, 127)),
  ],
  ['parseCidr /24', () => parseCidr('192.0.2.0/24'), r4(q(192, 0, 2, 0), q(192, 0, 2, 255))],
  ['parseCidr /0 v4', () => parseCidr('0.0.0.0/0'), r4(0n, q(255, 255, 255, 255))],
  ['parseCidr bare v4 = /32', () => parseCidr('192.0.2.9'), r4(q(192, 0, 2, 9), q(192, 0, 2, 9))],
  [
    'parseCidr v6 /32',
    () => parseCidr('2001:db8::/32'),
    { family: 6, start: DOC_V6, end: DOC_V6 + (1n << 96n) - 1n },
  ],
  [
    'parseCidr bare v6 = /128',
    () => parseCidr('2001:db8::5'),
    { family: 6, start: DOC_V6 + 5n, end: DOC_V6 + 5n },
  ],
  [
    'parseCidr mapped v4 with v6 prefix length',
    () => parseCidr('::ffff:192.0.2.0/120'),
    r4(q(192, 0, 2, 0), q(192, 0, 2, 255)),
  ],
  ['parseCidr rejects /33 on v4', () => parseCidr('192.0.2.0/33'), undefined],
  ['parseCidr rejects /129 on v6', () => parseCidr('2001:db8::/129'), undefined],
  ['parseCidr rejects leading-zero prefix', () => parseCidr('192.0.2.0/024'), undefined],
  ['parseCidr rejects empty prefix', () => parseCidr('192.0.2.0/'), undefined],
  ['parseCidr rejects negative prefix', () => parseCidr('192.0.2.0/-1'), undefined],
  ['parseCidr rejects bad address', () => parseCidr('192.0.2/24'), undefined],

  // --- parseIpRange ---
  [
    'parseIpRange nmap last-octet range',
    () => parseIpRange('192.0.2.1-20'),
    r4(q(192, 0, 2, 1), q(192, 0, 2, 20)),
  ],
  [
    'parseIpRange nmap wildcard',
    () => parseIpRange('192.0.2.*'),
    r4(q(192, 0, 2, 0), q(192, 0, 2, 255)),
  ],
  [
    'parseIpRange nmap range then wildcard',
    () => parseIpRange('198.51.100-101.*'),
    r4(q(198, 51, 100, 0), q(198, 51, 101, 255)),
  ],
  [
    'parseIpRange full addresses',
    () => parseIpRange('192.0.2.10-192.0.2.200'),
    r4(q(192, 0, 2, 10), q(192, 0, 2, 200)),
  ],
  [
    'parseIpRange v6 full addresses',
    () => parseIpRange('2001:db8::1-2001:db8::ff'),
    { family: 6, start: DOC_V6 + 1n, end: DOC_V6 + 0xffn },
  ],
  ['parseIpRange rejects reversed', () => parseIpRange('192.0.2.20-1'), undefined],
  ['parseIpRange rejects reversed full', () => parseIpRange('192.0.2.9-192.0.2.1'), undefined],
  ['parseIpRange rejects mixed families', () => parseIpRange('192.0.2.1-2001:db8::1'), undefined],
  [
    'parseIpRange rejects non-contiguous octet ranges',
    () => parseIpRange('192.0.1-3.5'),
    undefined,
  ],
  ['parseIpRange rejects octet > 255', () => parseIpRange('192.0.2.1-256'), undefined],
  ['parseIpRange rejects a single IP', () => parseIpRange('192.0.2.1'), undefined],

  // --- parseIpSpec ---
  [
    'parseIpSpec CIDR',
    () => parseIpSpec('198.51.100.0/24'),
    r4(q(198, 51, 100, 0), q(198, 51, 100, 255)),
  ],
  [
    'parseIpSpec range',
    () => parseIpSpec('203.0.113.5-9'),
    r4(q(203, 0, 113, 5), q(203, 0, 113, 9)),
  ],
  [
    'parseIpSpec single',
    () => parseIpSpec('203.0.113.5'),
    r4(q(203, 0, 113, 5), q(203, 0, 113, 5)),
  ],
  ['parseIpSpec rejects garbage', () => parseIpSpec('not-an-ip'), undefined],

  // --- formatRange ---
  ['formatRange round-trips /24', () => formatRange(spec('192.0.2.0/24')), '192.0.2.0/24'],
  ['formatRange round-trips /25', () => formatRange(spec('192.0.2.128/25')), '192.0.2.128/25'],
  ['formatRange round-trips /0', () => formatRange(spec('0.0.0.0/0')), '0.0.0.0/0'],
  ['formatRange round-trips v6 /32', () => formatRange(spec('2001:db8::/32')), '2001:db8::/32'],
  ['formatRange round-trips v6 /0', () => formatRange(spec('::/0')), '::/0'],
  ['formatRange single address', () => formatRange(spec('192.0.2.66')), '192.0.2.66/32'],
  ['formatRange normalises host bits', () => formatRange(spec('192.0.2.77/25')), '192.0.2.0/25'],
  ['formatRange non-CIDR range', () => formatRange(spec('192.0.2.1-20')), '192.0.2.1-192.0.2.20'],
  [
    'formatRange power-of-two size but unaligned',
    () => formatRange(spec('192.0.2.1-192.0.2.2')),
    '192.0.2.1-192.0.2.2',
  ],
  [
    'formatRange v6 non-CIDR range',
    () => formatRange(spec('2001:db8::1-2001:db8::ff')),
    '2001:db8::1-2001:db8::ff',
  ],

  // --- rangeContains / rangesIntersect ---
  [
    'rangeContains /24 contains /25',
    () => rangeContains(spec('192.0.2.0/24'), spec('192.0.2.128/25')),
    true,
  ],
  [
    'rangeContains /25 does not contain /24',
    () => rangeContains(spec('192.0.2.128/25'), spec('192.0.2.0/24')),
    false,
  ],
  [
    'rangeContains is false across families',
    () => rangeContains(spec('::/0'), spec('192.0.2.1')),
    false,
  ],
  [
    'rangesIntersect overlapping',
    () => rangesIntersect(spec('192.0.2.0-192.0.2.10'), spec('192.0.2.10-192.0.2.20')),
    true,
  ],
  [
    'rangesIntersect adjacent but disjoint',
    () => rangesIntersect(spec('192.0.2.0/25'), spec('192.0.2.128/25')),
    false,
  ],
  [
    'rangesIntersect is false across families',
    () => rangesIntersect(spec('0.0.0.0/0'), spec('::/0')),
    false,
  ],

  // --- coveredBy ---
  [
    'coveredBy two adjacent halves',
    () => coveredBy(spec('192.0.2.0/24'), [spec('192.0.2.0/25'), spec('192.0.2.128/25')]),
    true,
  ],
  [
    'coveredBy halves given out of order',
    () => coveredBy(spec('192.0.2.0/24'), [spec('192.0.2.128/25'), spec('192.0.2.0/25')]),
    true,
  ],
  [
    'coveredBy only the low half',
    () => coveredBy(spec('192.0.2.0/24'), [spec('192.0.2.0/25')]),
    false,
  ],
  [
    'coveredBy overlapping pieces',
    () =>
      coveredBy(spec('192.0.2.0/24'), [
        spec('192.0.2.0-192.0.2.100'),
        spec('192.0.2.50-192.0.2.200'),
        spec('192.0.2.180-192.0.2.255'),
      ]),
    true,
  ],
  [
    'coveredBy with a one-address gap',
    () => coveredBy(spec('192.0.2.0/24'), [spec('192.0.2.0-192.0.2.99'), spec('192.0.2.101-255')]),
    false,
  ],
  ['coveredBy empty cover', () => coveredBy(spec('192.0.2.1'), []), false],
  [
    'coveredBy ignores other-family cover',
    () => coveredBy(spec('192.0.2.1'), [spec('::/0')]),
    false,
  ],

  // --- subtractRanges ---
  [
    'subtractRanges punches a hole',
    () => subtractRanges(spec('192.0.2.0/25'), [spec('192.0.2.66')]),
    [r4(q(192, 0, 2, 0), q(192, 0, 2, 65)), r4(q(192, 0, 2, 67), q(192, 0, 2, 127))],
  ],
  [
    'subtractRanges everything',
    () => subtractRanges(spec('192.0.2.0/25'), [spec('192.0.2.0/24')]),
    [],
  ],
  [
    'subtractRanges nothing overlapping',
    () => subtractRanges(spec('192.0.2.0/25'), [spec('198.51.100.0/24'), spec('::/0')]),
    [r4(q(192, 0, 2, 0), q(192, 0, 2, 127))],
  ],
  [
    'subtractRanges unsorted overlapping minus',
    () =>
      subtractRanges(spec('192.0.2.0/24'), [
        spec('192.0.2.200-192.0.2.255'),
        spec('192.0.2.10-20'),
        spec('192.0.2.15-30'),
        spec('192.0.2.0'),
      ]),
    [r4(q(192, 0, 2, 1), q(192, 0, 2, 9)), r4(q(192, 0, 2, 31), q(192, 0, 2, 199))],
  ],

  // --- isPrivateLike ---
  ['isPrivateLike private', () => isPrivateLike('private'), true],
  ['isPrivateLike loopback', () => isPrivateLike('loopback'), true],
  ['isPrivateLike link-local', () => isPrivateLike('link-local'), true],
  ['isPrivateLike cgnat', () => isPrivateLike('cgnat'), true],
  ['isPrivateLike documentation counts as public', () => isPrivateLike('documentation'), false],
  ['isPrivateLike public', () => isPrivateLike('public'), false],
  ['isPrivateLike multicast', () => isPrivateLike('multicast'), false],
]

describe('scope/ip table', () => {
  it('has at least 40 rows', () => {
    expect(rows.length).toBeGreaterThanOrEqual(40)
  })

  it.each(rows)('%s', (_label, actual, expected) => {
    expect(actual()).toEqual(expected)
  })
})

const classes: [string, IpClass][] = [
  ['127.0.0.1', 'loopback'],
  ['127.255.255.254', 'loopback'],
  ['::1', 'loopback'],
  ['::ffff:127.0.0.1', 'loopback'],
  ['10.1.2.3', 'private'],
  ['172.16.0.1', 'private'],
  ['172.31.255.255', 'private'],
  ['172.32.0.1', 'public'],
  ['192.168.1.1', 'private'],
  ['fd00::1', 'private'],
  ['fc00::1', 'private'],
  ['100.64.0.1', 'cgnat'],
  ['100.127.255.255', 'cgnat'],
  ['100.128.0.1', 'public'],
  ['169.254.1.1', 'link-local'],
  ['fe80::1', 'link-local'],
  ['febf::1', 'link-local'],
  ['224.0.0.1', 'multicast'],
  ['239.255.255.250', 'multicast'],
  ['ff02::1', 'multicast'],
  ['0.0.0.0', 'unspecified'],
  ['::', 'unspecified'],
  ['192.0.2.1', 'documentation'],
  ['198.51.100.7', 'documentation'],
  ['203.0.113.9', 'documentation'],
  ['2001:db8::1', 'documentation'],
  ['3fff::1', 'documentation'],
  ['64:ff9b::808:808', 'public'],
  ['0.1.2.3', 'reserved'],
  ['240.0.0.1', 'reserved'],
  ['255.255.255.255', 'reserved'],
  ['198.18.0.1', 'reserved'],
  ['192.0.0.8', 'reserved'],
  ['100::1', 'reserved'],
  ['8.8.8.8', 'public'],
  ['1.1.1.1', 'public'],
  ['2606:4700:4700::1111', 'public'],
]

describe('classifyIp', () => {
  it.each(classes)('%s is %s', (addr, cls) => {
    expect(classifyIp(ip(addr))).toBe(cls)
  })

  it('classifies a hand-built family-6 mapped address by its IPv4 value', () => {
    expect(classifyIp({ family: 6, value: (0xffffn << 32n) + q(10, 0, 0, 1) })).toBe('private')
  })

  // Ruling P8: NAT64 (64:ff9b::/96) addresses are classified by the IPv4 address they embed.
  it.each([
    ['64:ff9b::808:808', 'public'],
    ['64:ff9b::127.0.0.1', 'loopback'],
    ['64:ff9b::10.0.0.5', 'private'],
    ['64:ff9b::192.168.1.1', 'private'],
    ['64:ff9b::169.254.169.254', 'link-local'],
    ['64:ff9b::100.64.0.1', 'cgnat'],
    ['64:ff9b::192.0.2.1', 'documentation'],
    ['64:ff9b::0.0.0.0', 'unspecified'],
  ] as [string, IpClass][])('NAT64 %s is %s', (addr, cls) => {
    expect(classifyIp(ip(addr))).toBe(cls)
  })

  it('does not treat addresses next to the NAT64 block as NAT64', () => {
    // 64:ff9b:0:0:0:1::/96 is outside 64:ff9b::/96 and falls into ::/8 (reserved).
    expect(classifyIp(ip('64:ff9b::1:7f00:1'))).toBe('reserved')
    expect(classifyIp(ip('64:ff9b:1::a00:5'))).toBe('reserved')
  })

  // Ruling P8: a malformed hand-built address fails closed instead of falling through to 'public'.
  it.each([
    ['negative IPv4 value', { family: 4, value: -1n }],
    ['IPv4 value above 2^32-1', { family: 4, value: 1n << 32n }],
    ['negative IPv6 value', { family: 6, value: -1n }],
    ['IPv6 value above 2^128-1', { family: 6, value: 1n << 128n }],
    ['unknown family', { family: 5, value: 1n }],
    ['non-bigint value', { family: 4, value: 134744072 }],
  ])('classifies a malformed address (%s) as reserved', (_label, bad) => {
    expect(classifyIp(bad as unknown as IpAddr)).toBe('reserved')
  })
})

describe('ipv6Embeddings', () => {
  it('gives the IPv4-mapped and NAT64 forms of an IPv4 range', () => {
    expect(ipv6Embeddings(spec('192.0.2.64/26'))).toEqual([
      // parseIp folds ::ffff:a.b.c.d to family 4, so the mapped form is built by hand.
      {
        family: 6,
        start: (0xffffn << 32n) | q(192, 0, 2, 64),
        end: (0xffffn << 32n) | q(192, 0, 2, 127),
      },
      { family: 6, start: ip('64:ff9b::192.0.2.64').value, end: ip('64:ff9b::192.0.2.127').value },
    ])
  })

  it('gives nothing for an IPv6 or malformed range', () => {
    expect(ipv6Embeddings(spec('2001:db8::/32'))).toEqual([])
    expect(ipv6Embeddings({ family: 4, start: 5n, end: 1n })).toEqual([])
  })
})

describe('invariants', () => {
  it('::ffff:a.b.c.d has the same value as a.b.c.d', () => {
    expect(ip('::ffff:192.0.2.66')).toEqual(ip('192.0.2.66'))
  })

  it('formatIp round-trips through parseIp', () => {
    for (const s of ['192.0.2.1', '::', '::1', '2001:db8::1', '2001:db8:0:1:1:1:1:1', 'fe80::1']) {
      expect(formatIp(ip(s))).toBe(s)
    }
  })

  it('formatRange output re-parses to the same range', () => {
    for (const s of ['192.0.2.0/24', '192.0.2.1-20', '2001:db8::/48', '2001:db8::1-2001:db8::ff']) {
      const r = spec(s)
      expect(parseIpSpec(formatRange(r))).toEqual(r)
    }
  })

  it('coveredBy(r, cover) agrees with subtractRanges(r, cover) being empty', () => {
    const r = spec('192.0.2.0/24')
    const cover = [spec('192.0.2.0-100'), spec('192.0.2.101-255')]
    expect(coveredBy(r, cover)).toBe(true)
    expect(subtractRanges(r, cover)).toEqual([])
  })

  it('rejects malformed ranges instead of treating them as covered', () => {
    const bad: IpRange = { family: 4, start: 10n, end: 5n }
    expect(coveredBy(bad, [spec('0.0.0.0/0')])).toBe(false)
    expect(rangeContains(spec('0.0.0.0/0'), bad)).toBe(false)
    expect(rangeContains(spec('0.0.0.0/0'), { family: 4, start: 0n, end: 1n << 32n })).toBe(false)
  })
})
