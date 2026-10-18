import { domainToASCII, domainToUnicode } from 'node:url'

// One DNS label after IDNA: 1–63 chars of [a-z0-9-], no leading or trailing hyphen.
const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/
// Any ASCII byte other than letters, digits, '-' and '.'. Rejected before IDNA because
// `domainToASCII` silently truncates at '/', '\', '?' and '#' and percent-decodes.
const ASCII_NON_HOST = /[\u0000-,/:-@[-`{-\u007f]/
const ALL_DIGITS = /^\d+$/
const NUMERIC_TOKEN = /^[\d.]+$/
const TLD = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/

/**
 * True when an `xn--` label decodes to Unicode and re-encodes to the same label. Done here
 * because how strictly `domainToASCII` rejects bad punycode varies between Node/ICU builds.
 */
function validPunycodeLabel(label: string): boolean {
  const unicode = domainToUnicode(label)
  if (unicode === '' || unicode.startsWith('xn--')) return false
  return domainToASCII(unicode) === label
}

/**
 * Canonical ASCII form of a DNS hostname, or `undefined` when `s` is not one.
 * Lowercases, strips one trailing dot and applies IDNA (UTS #46) via `domainToASCII`.
 * Names whose last label is numeric are rejected: URL parsers and `inet_aton` read them as
 * IPv4 addresses (`1.2.3`, `0x7f.1`), so they are never hostnames.
 */
export function normaliseHostname(s: string): string | undefined {
  if (s === '' || ASCII_NON_HOST.test(s)) return undefined
  let h = s.toLowerCase()
  const strippedDot = h.endsWith('.')
  if (strippedDot) h = h.slice(0, -1)
  if (h === '') return undefined
  let ascii = domainToASCII(h)
  // IDNA maps U+3002 / U+FF0E / U+FF61 to '.', so a trailing dot can first appear here.
  // Still only one trailing dot in total is stripped.
  if (!strippedDot && ascii.endsWith('.')) ascii = ascii.slice(0, -1)
  if (ascii === '' || ascii.length > 253) return undefined
  const labels = ascii.split('.')
  for (const label of labels) {
    if (!LABEL.test(label)) return undefined
    if (label.startsWith('xn--') && !validPunycodeLabel(label)) return undefined
  }
  if (ALL_DIGITS.test(labels[labels.length - 1] ?? '')) return undefined
  return ascii
}

export type HostPattern = { kind: 'exact'; host: string } | { kind: 'wildcard'; suffix: string }

/** `'*.x'` is a wildcard with suffix `x`; `*` is only allowed as the whole first label. */
export function parseHostPattern(s: string): HostPattern | undefined {
  if (s.startsWith('*.')) {
    const suffix = normaliseHostname(s.slice(2))
    return suffix === undefined ? undefined : { kind: 'wildcard', suffix }
  }
  const host = normaliseHostname(s)
  return host === undefined ? undefined : { kind: 'exact', host }
}

/**
 * Label-boundary match: `*.acme.example` matches `www.acme.example` and `a.b.acme.example`,
 * never `acme.example` itself, `evilacme.example` or `acme.example.attacker.example`.
 * `host` is normalised first; a value that is not a hostname never matches.
 */
export function hostMatches(p: HostPattern, host: string): boolean {
  const h = normaliseHostname(host)
  if (h === undefined) return false
  if (p.kind === 'exact') return h === p.host
  return h.endsWith(`.${p.suffix}`) && h !== p.suffix
}

/** Last labels that are almost always file names rather than TLDs in a command line. */
export const FILE_EXTENSIONS: ReadonlySet<string> = new Set([
  // source and scripts
  'py',
  'pyc',
  'js',
  'mjs',
  'cjs',
  'jsx',
  'ts',
  'mts',
  'cts',
  'tsx',
  'rb',
  'php',
  'java',
  'jar',
  'class',
  'cpp',
  'hpp',
  'sh',
  'bash',
  'zsh',
  'ps1',
  'psm1',
  'bat',
  'cmd',
  // data and docs
  'json',
  'jsonl',
  'md',
  'txt',
  'yaml',
  'yml',
  'xml',
  'html',
  'htm',
  'css',
  'csv',
  'tsv',
  'sql',
  'log',
  'pdf',
  'doc',
  'docx',
  'xls',
  'xlsx',
  'png',
  'jpg',
  'jpeg',
  'gif',
  'svg',
  // config and secrets
  'conf',
  'cfg',
  'ini',
  'toml',
  'lock',
  'env',
  'pem',
  'key',
  'crt',
  'cer',
  'der',
  'csr',
  'pfx',
  'p12',
  // binaries and archives
  'exe',
  'dll',
  'so',
  'dylib',
  'bin',
  'dat',
  'db',
  'sqlite',
  'gz',
  'tgz',
  'bz2',
  'xz',
  'tar',
  'zip',
  '7z',
  'rar',
  'iso',
  'img',
  'deb',
  'rpm',
  'msi',
  'whl',
  // scratch and tool output
  'bak',
  'tmp',
  'old',
  'orig',
  'patch',
  'swp',
  'out',
  'pcap',
  'pcapng',
  'nmap',
  'gnmap',
])

/**
 * Heuristic for the literal sweep: true for tokens that look like a fully qualified domain name.
 * Requires ≥ 2 labels, an alphabetic (or punycode) TLD of ≥ 2 chars that is not a file extension,
 * no path separator and not an all-numeric token.
 */
export function looksLikeFqdn(token: string): boolean {
  if (token.includes('/') || token.includes('\\')) return false
  if (NUMERIC_TOKEN.test(token)) return false
  const host = normaliseHostname(token)
  if (host === undefined) return false
  const labels = host.split('.')
  if (labels.length < 2) return false
  const tld = labels[labels.length - 1] ?? ''
  return TLD.test(tld) && !FILE_EXTENSIONS.has(tld)
}
