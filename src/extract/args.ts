import type { Tier } from '../policy/decisions.js'
import { parseTarget, type Target } from '../scope/target.js'
import type { RateKind } from './rate.js'
import type { EmbeddedForm, KnownToolSpec } from './tools-table.js'

/** URL scheme names: `http:8080` parses as host `http`, which is never a real target. */
export const URL_SCHEMES: ReadonlySet<string> = new Set([
  'http',
  'https',
  'ws',
  'wss',
  'ftp',
  'ftps',
  'sftp',
  'scp',
  'ssh',
  'telnet',
  'tftp',
  'smb',
  'nfs',
  'ldap',
  'ldaps',
  'rdp',
  'vnc',
  'winrm',
  'mysql',
  'mssql',
  'postgres',
  'postgresql',
  'redis',
  'mongodb',
  'file',
  'gopher',
  'dict',
  'imap',
  'imaps',
  'pop3',
  'pop3s',
  'smtp',
  'smtps',
  'rtsp',
  'git',
  'svn',
  'socks',
  'socks4',
  'socks5',
])

/** Credentialed header values: Authorization, Proxy-Authorization, API-key and Cookie headers (P17). */
export const AUTH_HEADER =
  /^\s*(?:(?:proxy-)?authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|cookie)\s*:/i

export const TIER_RANK: Readonly<Record<Tier | 'dos', number>> = {
  recon: 0,
  'vuln-scan': 1,
  bruteforce: 2,
  exploitation: 3,
  'post-exploitation': 4,
  dos: 5,
}

const PORT_LIST = /^\d+(?:[-,]\d+)*$/
const UNC = /^(?:\\\\|\/\/)([^\\/]+)/
const URL_START = /^[a-z][a-z0-9+.-]*:\/\//i
// scp/rsync/git remote: `[user@]host:path` with no slash before the colon (`host::module` too).
const REMOTE_PATH = /^(?:([^@/]*)@)?(\[[^\]]+\]|[^/:@\\]+):/
const GO_STYLE_FLAG = /^-[A-Za-z][A-Za-z0-9-]{2,}$/

// ---- flag index ---------------------------------------------------------------------------------

export interface FlagRole {
  takesValue: boolean
  /** The value is optional: the next word is taken only when it does not start with `-`. */
  optionalValue: boolean
  host: boolean
  url: boolean
  file: boolean
  urlOrFile: boolean
  exclude: boolean
  excludeFile: boolean
  infra: boolean
  nonTarget: boolean
  nonNetwork: boolean
  credential: boolean
  credentialHeader: boolean
  bruteforceFile: boolean
  embedded: EmbeddedForm | null
  /** `-c key=value` config flags whose value is infrastructure when `key` matches. */
  infraConfig: RegExp[]
  rate: RateKind | null
  /** Implied value of a rate switch (hping3 `--fast`). */
  rateValue: string | null
  hardDeny: string | null
  overrides: NonNullable<KnownToolSpec['tierOverrides']>
}

export interface FlagIndex {
  roles: Map<string, FlagRole>
  /** Attached short values (`-T4`, `-p80`) are allowed unless the tool uses Go-style `-name` flags. */
  attachedShort: boolean
  cluster: boolean
}

export function buildIndex(spec: KnownToolSpec): FlagIndex {
  const roles = new Map<string, FlagRole>()
  const role = (flag: string): FlagRole => {
    let r = roles.get(flag)
    if (!r) {
      r = {
        takesValue: false,
        optionalValue: false,
        host: false,
        url: false,
        file: false,
        urlOrFile: false,
        exclude: false,
        excludeFile: false,
        infra: false,
        nonTarget: false,
        nonNetwork: false,
        credential: false,
        credentialHeader: false,
        bruteforceFile: false,
        embedded: null,
        infraConfig: [],
        rate: null,
        rateValue: null,
        hardDeny: null,
        overrides: [],
      }
      roles.set(flag, r)
    }
    return r
  }
  const mark = (flags: string[] | undefined, apply: (r: FlagRole) => void, value = true) => {
    for (const f of flags ?? []) {
      const r = role(f)
      apply(r)
      if (value) r.takesValue = true
    }
  }
  mark(spec.hostFlags, (r) => (r.host = true))
  mark(spec.urlFlags, (r) => (r.url = true))
  mark(spec.fileFlags, (r) => (r.file = true))
  mark(spec.urlOrFileFlags, (r) => (r.urlOrFile = true))
  mark(spec.excludeFlags, (r) => (r.exclude = true))
  mark(spec.excludeFileFlags, (r) => (r.excludeFile = true))
  mark(spec.infraFlags, (r) => (r.infra = true))
  mark(spec.nonTargetFlags, (r) => (r.nonTarget = true))
  mark(spec.valueFlags, () => {})
  mark(spec.optionalValueFlags, (r) => (r.optionalValue = true))
  mark(spec.credentialHeaderFlags, (r) => (r.credentialHeader = true))
  mark(spec.nonNetworkFlags, (r) => (r.nonNetwork = true), false)
  mark(spec.credentialFlags, (r) => (r.credential = true), false)
  mark(spec.bruteforceFileFlags, (r) => (r.bruteforceFile = true), false)
  for (const e of spec.embeddedFlags ?? []) {
    const r = role(e.flag)
    r.embedded = e.form
    r.takesValue = true
  }
  for (const c of spec.infraConfigFlags ?? []) {
    const r = role(c.flag)
    r.infraConfig.push(c.key)
    r.takesValue = true
  }
  for (const rf of spec.rateFlags ?? []) {
    const r = role(rf.flag)
    r.rate = rf.kind
    r.rateValue = rf.value ?? null
    if (rf.value === undefined) r.takesValue = true
  }
  for (const h of spec.hardDenyFlags ?? []) role(h.flag).hardDeny = h.reason
  for (const o of spec.tierOverrides ?? []) role(o.flag).overrides.push(o)
  const goStyle = [...roles.keys()].some((f) => GO_STYLE_FLAG.test(f))
  return { roles, attachedShort: !goStyle, cluster: spec.clusterShortFlags === true }
}

export interface FlagMatch {
  name: string
  attached?: string
}

/**
 * `--name` ↔ `-name` for names longer than one letter (getopt_long_only and Go flag parsing). Not
 * for clustering tools: `curl -version` is `-v -e rsion`, never `--version`.
 */
function resolveName(idx: FlagIndex, n: string): string | undefined {
  if (idx.roles.has(n)) return n
  if (idx.cluster) return undefined
  if (n.startsWith('--') && n.length > 3 && idx.roles.has(n.slice(1))) return n.slice(1)
  if (/^-[^-]/.test(n) && n.length > 2 && idx.roles.has(`-${n}`)) return `-${n}`
  return undefined
}

/** The flags one option word stands for (several for a getopt cluster), or `[]` when unknown. */
export function matchFlag(idx: FlagIndex, tok: string): FlagMatch[] {
  const direct = resolveName(idx, tok)
  if (direct) return [{ name: direct }]
  const eq = tok.indexOf('=')
  if (eq > 0) {
    const name = resolveName(idx, tok.slice(0, eq))
    if (name) return [{ name, attached: tok.slice(eq + 1) }]
  }
  const colon = tok.indexOf(':')
  if (tok.startsWith('/') && colon > 0 && idx.roles.has(tok.slice(0, colon))) {
    return [{ name: tok.slice(0, colon), attached: tok.slice(colon + 1) }]
  }
  if (!tok.startsWith('-') || tok.startsWith('--') || tok.length <= 2) return []
  const short = tok.slice(0, 2)
  if (idx.attachedShort && idx.roles.get(short)?.takesValue) {
    return [{ name: short, attached: tok.slice(2) }]
  }
  if (!idx.cluster || !/^-[A-Za-z0-9]{2,}$/.test(tok)) return []
  const out: FlagMatch[] = []
  for (let k = 1; k < tok.length; k++) {
    const f = `-${tok[k]}`
    const r = idx.roles.get(f)
    if (r?.takesValue) {
      const rest = tok.slice(k + 1)
      out.push(rest === '' ? { name: f } : { name: f, attached: rest })
      break
    }
    if (r) out.push({ name: f })
  }
  return out
}

const MERGED_LISTS = [
  'hostFlags',
  'urlFlags',
  'fileFlags',
  'urlOrFileFlags',
  'excludeFlags',
  'excludeFileFlags',
  'infraFlags',
  'nonTargetFlags',
  'valueFlags',
  'optionalValueFlags',
  'bruteforceFileFlags',
  'embeddedFlags',
  'infraConfigFlags',
  'tierOverrides',
  'hardDenyFlags',
  'rateFlags',
  'credentialFlags',
  'credentialHeaderFlags',
] as const

/**
 * Flag lists are concatenated and scalar fields of the subcommand replace the parent's.
 * `nonNetworkFlags` are deliberately NOT inherited: `docker run -v` or `gem install -v 7.0` are not
 * version prints, so only the subcommand's own non-network flags apply.
 */
export function mergeSpec(top: KnownToolSpec, sub: Partial<KnownToolSpec>): KnownToolSpec {
  const merged: KnownToolSpec = { ...top, ...sub, names: top.names }
  for (const key of MERGED_LISTS) {
    const a = (top[key] ?? []) as unknown[]
    const b = (sub[key] ?? []) as unknown[]
    if (a.length + b.length > 0) {
      ;(merged as unknown as Record<string, unknown[]>)[key] = [...b, ...a]
    }
  }
  if (sub.nonNetworkFlags) merged.nonNetworkFlags = sub.nonNetworkFlags
  else delete merged.nonNetworkFlags
  delete merged.subcommands
  delete merged.localSubcommands
  return merged
}

// ---- target tokens ------------------------------------------------------------------------------

export interface ParsedToken {
  raw: string
  target: Target
  credentials: boolean
}

/** Host part after the last `@`, without a `:path` or `/path` suffix (a numeric `:port` is kept). */
function hostAfterAt(s: string): string {
  const host = s.slice(s.lastIndexOf('@') + 1)
  if (host.startsWith('[')) return host
  const slash = host.indexOf('/')
  const noPath = slash >= 0 ? host.slice(0, slash) : host
  const colon = noPath.indexOf(':')
  if (colon < 0) return noPath
  return /^\d{1,5}$/.test(noPath.slice(colon + 1)) ? noPath : noPath.slice(0, colon)
}

/**
 * A token in a target position: UNC `//host/share`, `[user[:pass]@]host`, or anything
 * `parseTarget` reads. `'skip'` for a port or port list (`nc host 80`), `undefined` when it does not
 * parse or names a URL scheme (`http:8080`).
 */
export function parseTargetToken(tok: string): ParsedToken | 'skip' | undefined {
  // `20-80`, `22,80` are port lists; a single decimal is left to parseTarget (≥ 2^24 is an IPv4).
  if (PORT_LIST.test(tok) && !/^\d+$/.test(tok)) return 'skip'
  let s = tok
  let credentials = false
  const unc = UNC.exec(s)
  if (unc) s = unc[1] as string
  else if (!s.includes('://') && s.includes('@')) {
    credentials = s.slice(0, s.lastIndexOf('@')).includes(':')
    s = hostAfterAt(s)
  }
  const target = s === '' ? undefined : parseTarget(s)
  if (!target) return PORT_LIST.test(tok) ? 'skip' : undefined
  if (target.kind === 'host' && URL_SCHEMES.has(target.host)) return undefined
  if (target.kind === 'url' && target.hadCredentials) credentials = true
  return { raw: s, target, credentials }
}

/** The target of a remote-looking positional (URL or scp-style), or `undefined` for a local path. */
export function remoteToken(tok: string): string | undefined {
  if (URL_START.test(tok)) return /^file:/i.test(tok) ? undefined : tok
  const m = REMOTE_PATH.exec(tok)
  if (!m) return undefined
  const host = m[2] as string
  if (/^[A-Za-z]$/.test(host)) return undefined // `C:\path`
  return host
}

/** A target-list value: host/URL lists are split on commas and blanks. */
export function listParts(value: string): string[] {
  return value.split(/[\s,]+/).filter((p) => p !== '')
}

// ---- embedded destinations ----------------------------------------------------------------------

export interface EmbeddedHit {
  raw: string
  role: 'target' | 'infra'
}

/** Splits on `:` outside `[…]` (IPv6 literals). */
function splitColons(s: string): string[] {
  const out: string[] = []
  let depth = 0
  let cur = ''
  for (const ch of s) {
    if (ch === '[') depth++
    else if (ch === ']') depth = Math.max(0, depth - 1)
    if (ch === ':' && depth === 0) {
      out.push(cur)
      cur = ''
    } else cur += ch
  }
  out.push(cur)
  return out
}

const hostPort = (host: string, port: string) => (port === '' ? host : `${host}:${port}`)
const isBindAny = (bind: string) => bind === '' || bind === '*'

/**
 * Destinations embedded in a flag value: curl `--resolve host:port:addr[,addr]`, curl
 * `--connect-to h1:p1:h2:p2`, ssh `-L`/`-R` `[bind:]port:host:hostport` (host is a target, bind is
 * infra) and ssh `-D [bind:]port` (bind is infra). Unix-socket forms yield nothing.
 */
export function embeddedTargets(form: EmbeddedForm, value: string): EmbeddedHit[] {
  switch (form) {
    case 'curl-resolve': {
      const parts = splitColons(value.replace(/^\+/, ''))
      if (parts.length < 3) return []
      return parts
        .slice(2)
        .join(':')
        .split(',')
        .filter((a) => a !== '')
        .map((raw) => ({ raw, role: 'target' as const }))
    }
    case 'curl-connect-to': {
      const parts = splitColons(value)
      const host = parts[2] ?? ''
      if (parts.length !== 4 || host === '') return []
      return [{ raw: hostPort(host, parts[3] ?? ''), role: 'target' }]
    }
    case 'ssh-forward': {
      const parts = splitColons(value)
      if (parts.length !== 3 && parts.length !== 4) return []
      const out: EmbeddedHit[] = []
      const bind = parts.length === 4 ? (parts[0] ?? '') : ''
      const host = parts[parts.length - 2]
      const port = parts[parts.length - 1]
      if (!isBindAny(bind)) out.push({ raw: bind, role: 'infra' })
      if (host !== undefined && port !== undefined && /^\d+$/.test(port)) {
        out.push({ raw: hostPort(host, port), role: 'target' })
      }
      return out
    }
    case 'ssh-dynamic': {
      const parts = splitColons(value)
      const bind = parts.length === 2 ? (parts[0] ?? '') : ''
      return isBindAny(bind) ? [] : [{ raw: bind, role: 'infra' }]
    }
  }
}

// bash `/dev/tcp/host/port` and `/dev/udp/host/port` pseudo-files; the port may be a service name.
const DEV_NET = /\/dev\/(?:tcp|udp)\/([^/\s'"`;|&<>()]+)\/([A-Za-z0-9_-]+)/g
// gawk `/inet[46]/tcp|udp/lport/rhost/rport` special files (rhost `0` = listen only).
const INET = /\/inet[46]?\/(?:tcp|udp)\/[A-Za-z0-9_-]+\/([^/\s'"`;|&<>()]+)\/([A-Za-z0-9_-]+)/g
// Well-known service names (IANA) bash resolves through getservbyname for /dev/tcp ports.
const SERVICE_PORTS: Readonly<Record<string, number>> = {
  ftp: 21,
  ssh: 22,
  telnet: 23,
  smtp: 25,
  domain: 53,
  http: 80,
  pop3: 110,
  imap: 143,
  ldap: 389,
  https: 443,
  smb: 445,
  'microsoft-ds': 445,
  ldaps: 636,
  imaps: 993,
  pop3s: 995,
  mysql: 3306,
  'ms-wbt-server': 3389,
  rdp: 3389,
  postgresql: 5432,
}

export interface DeviceHit {
  /** `host:port` (or the host alone for an unknown service name). */
  raw: string
  host: string
}

/** Destinations of shell `/dev/tcp`/`/dev/udp` paths and gawk `/inet` files in `text`. */
export function deviceTargets(text: string): DeviceHit[] {
  const out: DeviceHit[] = []
  for (const re of [DEV_NET, INET]) {
    for (const m of text.matchAll(re)) {
      const host = m[1] as string
      if (host === '0') continue
      const h = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host
      const svc = m[2] as string
      const port = /^\d+$/.test(svc) ? svc : SERVICE_PORTS[svc.toLowerCase()]
      out.push({ raw: port === undefined ? h : `${h}:${port}`, host })
    }
  }
  return out
}
