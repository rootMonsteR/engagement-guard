import { domainToASCII, URL } from 'node:url'
import { normaliseHostname } from './hostname.js'
import { formatIp, type IpAddr, type IpRange, parseIp, parseIpSpec } from './ip.js'

export type Target =
  | { kind: 'ip'; raw: string; ip: IpAddr; port?: number }
  | { kind: 'range'; raw: string; range: IpRange }
  | { kind: 'host'; raw: string; host: string; port?: number }
  | {
      kind: 'url'
      raw: string
      scheme: string
      host: string
      ip?: IpAddr
      port: number
      path: string
      hadCredentials: boolean
    }

const DEFAULT_PORTS: ReadonlyMap<string, number> = new Map([
  ['http', 80],
  ['https', 443],
  ['ws', 80],
  ['wss', 443],
  ['ftp', 21],
  ['ssh', 22],
  ['smb', 445],
  ['ldap', 389],
  ['ldaps', 636],
  ['rdp', 3389],
  ['mysql', 3306],
  ['postgres', 5432],
  ['redis', 6379],
  ['mongodb', 27017],
])

const SCHEME_URL = /^([a-z][a-z0-9+.-]*):\/\/(.*)$/i
// `scheme:/rest` (one slash). WHATWG reads it as `scheme://rest` for special schemes.
const SCHEME_SINGLE_SLASH = /^([a-z][a-z0-9+.-]*):\/(?!\/)(.*)$/i
const BARE_SCHEME = /^[a-z][a-z0-9+.-]*:$/i
// A bare decimal integer below 2^24 is far more likely a port, count or size than an IPv4 address.
const DECIMAL = /^\d+$/
const MIN_BARE_DECIMAL_IPV4 = 16_777_216n
// Whitespace and control characters never appear in a target token.
const BAD_CHARS = /[\s\u0000-\u001f\u007f]/
// Structural characters that must not survive into a bare host (ports and brackets are split first).
const HOST_DELIMITERS = /[/\\?#@:[\]]/
const PORT = /^\d{1,5}$/
const CIDR_SUFFIX = /^\/\d+$/

type HostPart = { ip: IpAddr } | { host: string }

/**
 * Canonical host: a bracketed IPv6 literal, an IP, a legacy numeric IPv4 form that URL parsers
 * accept (`0xc0.0.2.10`, `3221225994`; canonicalised rather than dropped) or a hostname.
 * `domainToASCII` applies the WHATWG host rules: percent-decoding, IDNA and IPv4 number parsing.
 * `bare` (a token outside a URL): a decimal integer below 2^24 is not read as an address.
 */
function canonicalHost(h: string, bare: boolean): HostPart | undefined {
  if (h.startsWith('[')) {
    if (!h.endsWith(']')) return undefined
    const inner = h.slice(1, -1)
    if (!inner.includes(':')) return undefined
    const ip = parseIp(inner)
    return ip ? { ip } : undefined
  }
  if (h === '' || HOST_DELIMITERS.test(h)) return undefined
  const direct = parseIp(h)
  if (direct) return { ip: direct }
  if (bare && DECIMAL.test(h) && BigInt(h) < MIN_BARE_DECIMAL_IPV4) return undefined
  const ascii = domainToASCII(h)
  if (ascii === '') return undefined
  const legacy = parseIp(ascii.endsWith('.') ? ascii.slice(0, -1) : ascii)
  if (legacy) return { ip: legacy }
  const host = normaliseHostname(ascii)
  return host === undefined ? undefined : { host }
}

function parsePort(text: string): number | undefined {
  if (!PORT.test(text)) return undefined
  const port = Number(text)
  return port >= 1 && port <= 65535 ? port : undefined
}

/** Splits `host`, `host:port`, `[v6]` or `[v6]:port`. `portText` is `''` for a trailing colon. */
function splitHostPort(
  s: string,
  bare: boolean,
): { part: HostPart; portText: string | undefined } | undefined {
  let hostText = s
  let portText: string | undefined
  if (s.startsWith('[')) {
    const close = s.indexOf(']')
    if (close < 0) return undefined
    hostText = s.slice(0, close + 1)
    const rest = s.slice(close + 1)
    if (rest !== '') {
      if (!rest.startsWith(':')) return undefined
      portText = rest.slice(1)
    }
  } else {
    const colon = s.indexOf(':')
    if (colon >= 0) {
      hostText = s.slice(0, colon)
      portText = s.slice(colon + 1)
    }
  }
  const part = canonicalHost(hostText, bare)
  return part ? { part, portText } : undefined
}

function hostOrIp(raw: string, part: HostPart, port: number | undefined): Target {
  const withPort = port === undefined ? {} : { port }
  return 'ip' in part
    ? { kind: 'ip', raw, ip: part.ip, ...withPort }
    : { kind: 'host', raw, host: part.host, ...withPort }
}

/** Path component only (query and fragment dropped), with dot segments resolved like a browser. */
function normalisePath(rest: string): string | undefined {
  const end = rest.search(/[?#]/)
  const path = end < 0 ? rest : rest.slice(0, end)
  if (path === '') return '/'
  try {
    return new URL(`http://h${path}`).pathname
  } catch {
    return undefined
  }
}

function buildUrl(
  raw: string,
  scheme: string,
  defaultPort: number,
  authority: string,
  rest: string,
  bare: boolean,
): Target | undefined {
  const at = authority.lastIndexOf('@')
  const split = splitHostPort(authority.slice(at + 1), bare)
  if (!split) return undefined
  const port =
    split.portText === undefined || split.portText === '' ? defaultPort : parsePort(split.portText)
  const path = normalisePath(rest)
  if (port === undefined || path === undefined) return undefined
  const { part } = split
  const common = { kind: 'url' as const, raw, scheme, port, path, hadCredentials: at >= 0 }
  return 'ip' in part
    ? { ...common, host: formatIp(part.ip), ip: part.ip }
    : { ...common, host: part.host }
}

function parseUrl(raw: string, scheme: string, rest: string): Target | undefined {
  const end = rest.search(/[/?#]/)
  const authority = end < 0 ? rest : rest.slice(0, end)
  const after = end < 0 ? '' : rest.slice(end)
  // Parsers disagree on '\' in the authority (WHATWG: path separator; curl: userinfo byte).
  if (authority.includes('\\')) return undefined
  const defaultPort = DEFAULT_PORTS.get(scheme)
  if (defaultPort !== undefined) return buildUrl(raw, scheme, defaultPort, authority, after, false)
  // Unlisted scheme: there is no default port, but the host must stay visible to the scope check.
  const split = splitHostPort(authority.slice(authority.lastIndexOf('@') + 1), false)
  if (!split) return undefined
  if (split.portText === undefined || split.portText === '') {
    return hostOrIp(raw, split.part, undefined)
  }
  const port = parsePort(split.portText)
  return port === undefined ? undefined : hostOrIp(raw, split.part, port)
}

/**
 * Parses one command-line token as a network target: IP, `[v6]:port`, `ip:port`, CIDR, IP range,
 * host, `host:port`, URL (scheme default port; userinfo stripped and flagged) or a scheme-less
 * `host/path` (an `http` URL). Returns `undefined` for anything else.
 */
export function parseTarget(raw: string): Target | undefined {
  const s = raw.trim()
  if (s === '' || s.startsWith('-') || BAD_CHARS.test(s)) return undefined

  const url = SCHEME_URL.exec(s)
  if (url) return parseUrl(raw, (url[1] ?? '').toLowerCase(), url[2] ?? '')
  // `http:/evil.example/x` must never yield `http` as the host: a listed scheme is read as
  // `scheme://rest` (as browsers do); anything else with one slash is rejected.
  const single = SCHEME_SINGLE_SLASH.exec(s)
  if (single) {
    const scheme = (single[1] ?? '').toLowerCase()
    return DEFAULT_PORTS.has(scheme) ? parseUrl(raw, scheme, single[2] ?? '') : undefined
  }

  const ip = parseIp(s)
  if (ip) return { kind: 'ip', raw, ip }
  const range = parseIpSpec(s)
  if (range) return { kind: 'range', raw, range }

  if (s.includes('@')) return undefined
  const slash = s.indexOf('/')
  if (slash >= 0) {
    const head = s.slice(0, slash)
    const tail = s.slice(slash)
    // `ip/<digits>` that parseIpSpec refused is a malformed CIDR, not a path.
    if (parseIp(head) && CIDR_SUFFIX.test(tail)) return undefined
    if (head === '' || BARE_SCHEME.test(head)) return undefined
    return buildUrl(raw, 'http', 80, head, tail, true)
  }

  const split = splitHostPort(s, true)
  if (!split) return undefined
  if (split.portText === undefined) return hostOrIp(raw, split.part, undefined)
  const port = parsePort(split.portText)
  return port === undefined ? undefined : hostOrIp(raw, split.part, port)
}

function formatRange(r: IpRange): string {
  const width = r.family === 4 ? 32 : 128
  const size = r.end - r.start + 1n
  const isPowerOfTwo = (size & (size - 1n)) === 0n
  if (isPowerOfTwo && (r.start & (size - 1n)) === 0n) {
    const prefix = width - (size.toString(2).length - 1)
    return `${formatIp({ family: r.family, value: r.start })}/${prefix}`
  }
  const start = formatIp({ family: r.family, value: r.start })
  const end = formatIp({ family: r.family, value: r.end })
  return `${start}-${end}`
}

/** Display form used in messages and audit records: the canonical host, IP or range. */
export function targetHost(t: Target): string {
  switch (t.kind) {
    case 'ip':
      return formatIp(t.ip)
    case 'range':
      return formatRange(t.range)
    case 'host':
    case 'url':
      return t.host
  }
}
