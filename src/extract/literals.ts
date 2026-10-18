import { looksLikeFqdn } from '../scope/hostname.js'
import { parseIp, parseIpSpec } from '../scope/ip.js'
import { parseTarget, type Target } from '../scope/target.js'

export interface LiteralHit {
  raw: string
  target: Target
}

// A URL anywhere in a token: `https://x`, `url=https://x`, `Referer:https://x`.
const URL_IN_TOKEN = /[a-z][a-z0-9+.-]*:\/\/[^\s'"<>`]+/gi
// Version specifiers (`pkg==1.2`, `pkg>=1`, `~=`, `!=`) never contain a target.
const VERSION_SPECIFIER = /[=<>!~]=/
// Semver-ish text after `@` (`lodash@4.17.21`, `@types/node@^20`, `pkg@v1.2.3-rc.1`).
const AT_VERSION = /^[~^v]?\d+(?:\.\d+){0,2}(?:[-+][0-9A-Za-z.-]+)?$/
const SEMVER = /^v?\d+\.\d+\.\d+$/
const OID = /^\d+(?:\.\d+){4,}$/
const IP_PORT = /^(.+):(\d{1,5})$/
// `TCP-CONNECT:host:port`, `ssh:host`: a leading word that is not itself a host.
const PREFIX_WORD = /^[A-Za-z][A-Za-z0-9-]*:(?!\/\/)(.+)$/
const UNC = /^(?:\\\\|\/\/)([^\\/]+)/
const LEADING_JUNK = /^[('"<]+/
const TRAILING_JUNK = /[)'">.,;:!?]+$/
// `$NAME`, `${…}`, `$1`, `$@`, a lone `$`: shell expansions whose value is unknown.
const EXPANSION = /\$(?:\{[^}]*\}?|[A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])?/g
// `${NAME:-word}`, `${NAME-word}`, `${NAME:=word}`, `${NAME=word}`: the default `word` may be used.
const WITH_DEFAULT = /^\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=](.*)\}$/

/** Blanks an expansion out, keeping a `${X:-default}` default word (it is a possible value). */
function blankExpansion(m: string): string {
  const d = WITH_DEFAULT.exec(m)
  return d ? ` ${d[1]} ` : ' '
}

// `-h198.51.100.9`: a single-letter option with its value attached.
const ATTACHED_SHORT = /^-[A-Za-z][^-=]/
// Separators inside a token (code strings, lists): blanks, commas, quotes, parentheses, braces.
const PIECE_SEPARATORS = /[\s,;()'"`{}|]+/

/** The host part of `[user@]host[:path]` after the last `@`, or `undefined` for a version. */
function afterAt(s: string): string | undefined {
  const host = s.slice(s.lastIndexOf('@') + 1)
  if (host === '' || (AT_VERSION.test(host) && !parseIp(host))) return undefined
  if (host.startsWith('[')) return host
  const slash = host.indexOf('/')
  const noPath = slash >= 0 ? host.slice(0, slash) : host
  const colon = noPath.indexOf(':')
  if (colon < 0 || parseIp(noPath)) return noPath
  const rest = noPath.slice(colon + 1)
  return /^\d{1,5}$/.test(rest) ? noPath : noPath.slice(0, colon)
}

/** True when `s` (no scheme) is an address-like literal worth parsing as a target. */
function looksLikeTarget(s: string): boolean {
  if (OID.test(s) || SEMVER.test(s)) return false
  if (parseIp(s) || parseIpSpec(s)) return true
  if (s.startsWith('[')) return /^\[[0-9a-f:.]+\](?::\d{1,5})?$/i.test(s)
  const slash = s.indexOf('/')
  const head = slash >= 0 ? s.slice(0, slash) : s
  if (head === '') return false
  const port = IP_PORT.exec(head)
  const host = port ? (port[1] as string) : head
  if (port && parseIp(host)?.family === 4) return true
  if (slash < 0 && port === null && parseIp(head)) return true
  return looksLikeFqdn(host)
}

/** Parses one cleaned piece; peels one `WORD:` prefix (socat/address heads) when needed. */
function evaluate(piece: string): LiteralHit | undefined {
  const s = piece.replace(LEADING_JUNK, '').replace(TRAILING_JUNK, '')
  if (s === '' || s.startsWith('-')) return undefined
  const unc = UNC.exec(s)
  if (unc) return evaluate(unc[1] as string)
  if (s.includes('@')) {
    const host = afterAt(s)
    return host === undefined ? undefined : evaluate(host)
  }
  if (looksLikeTarget(s)) {
    const target = parseTarget(s)
    if (target) return { raw: s, target }
  }
  const peeled = PREFIX_WORD.exec(s)
  if (peeled && !looksLikeFqdn(s.slice(0, s.indexOf(':')))) return evaluate(peeled[1] as string)
  return undefined
}

/** Candidate substrings of one token, in order: URLs first, then the pieces between separators. */
function candidates(token: string, attachedShort: boolean): string[] {
  // An expansion's value is unknown: blank it out and sweep the text around it.
  let t = token.replace(EXPANSION, blankExpansion)
  if (t.startsWith('-') || t.startsWith('+')) {
    const eq = t.indexOf('=')
    if (eq >= 0) t = t.slice(eq + 1)
    else if (attachedShort && ATTACHED_SHORT.test(t)) t = t.slice(2)
    else return []
  }
  const urls = (t.match(URL_IN_TOKEN) ?? []).map((u) => u.replace(TRAILING_JUNK, ''))
  const rest = urls.length > 0 ? t.replace(URL_IN_TOKEN, ' ') : t
  const pieces: string[] = []
  for (const raw of rest.split(PIECE_SEPARATORS)) {
    if (raw === '' || raw.startsWith('-') || VERSION_SPECIFIER.test(raw)) continue
    const eq = raw.indexOf('=')
    pieces.push(eq >= 0 ? raw.slice(eq + 1) : raw)
  }
  return [...urls, ...pieces.filter((p) => p !== '')]
}

function urlHit(u: string): LiteralHit | undefined {
  if (/^file:/i.test(u)) return undefined
  const target = parseTarget(u)
  return target ? { raw: u, target } : undefined
}

/**
 * Literal sweep: IPs, CIDRs and ranges, IPv6 (bracketed or bare), URLs and FQDNs found in each token,
 * including inside `k=v`, `--opt=v`, `user@host` and `user@host:path` forms. `$NAME` / `${…}`
 * expansions are blanked out and the rest of the token is still swept. Filters: pieces with a
 * version specifier (`==`, `>=` …), text after `@` that is a version, file extensions (via
 * `looksLikeFqdn`), OIDs, semver-looking `a.b.c`, and `-`-prefixed option names. With
 * `attachedShort` (unknown programs) the value of `-hVALUE` is swept too.
 * Results are deduplicated by `raw`, first occurrence first.
 */
export function sweepLiterals(
  argv: string[],
  opts: { attachedShort?: boolean } = {},
): LiteralHit[] {
  const out: LiteralHit[] = []
  const seen = new Set<string>()
  for (const token of argv) {
    for (const c of candidates(token, opts.attachedShort === true)) {
      const hit = c.includes('://') ? urlHit(c) : evaluate(c)
      if (hit && !seen.has(hit.raw)) {
        seen.add(hit.raw)
        out.push(hit)
      }
    }
  }
  return out
}
