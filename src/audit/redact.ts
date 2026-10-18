/**
 * Secret redaction for audit records (spec §6.6): applied to `command`, target `raw` values and
 * every string leaf of `data` before a record is hashed and written. Patterns favour removing a
 * secret over keeping context, but each one is anchored so that look-alikes (port lists, URLs
 * without credentials, flags that merely contain "token", …) pass through unchanged; see
 * `test/fixtures/redaction-corpus.yaml`. `redact` is idempotent.
 */

export const REDACTED = '[REDACTED]'

/** A quoted or bare shell-ish value. */
const VALUE = String.raw`(?:'[^']*'|"[^"]*"|[^\s'"]+)`

/** Replaces a value, keeping its surrounding quotes. */
function mask(value: string): string {
  const q = value[0]
  if ((q === "'" || q === '"') && value.length >= 2 && value.endsWith(q))
    return `${q}${REDACTED}${q}`
  return REDACTED
}

/** `-----BEGIN … PRIVATE KEY-----` blocks, also when the END line is missing (truncated output). */
const PRIVATE_KEY =
  /-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY( BLOCK)?-----[\s\S]*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|$)/g

/** `scheme://user:password@host` — the password is redacted, the user kept. */
const URL_USERINFO = /(?<![a-z0-9+.-])([a-z][a-z0-9+.-]*:\/\/)([^\s:/@'"]+):([^\s/'"]+)@/gi

/** `(Proxy-)Authorization`, `Cookie`, API-key headers: the value (after any auth scheme). */
const HEADER =
  /\b((?:Proxy-)?Authorization|Set-Cookie|Cookie|X-Api-Key|X-Auth-Token)(["']?\s*:\s*)(["']?)((?:Bearer|Basic|Digest|NTLM|Negotiate|Token)\s+)?([^\r\n'"]+)/gi

/** `Bearer <token>` / `Basic <b64>` outside a header; plain words ("Basic authentication") are kept. */
const AUTH_SCHEME =
  /\b([Bb]earer|[Bb]asic)(\s+)(?=[A-Za-z0-9._~+/=-]*[A-Z0-9+/=._~-])[A-Za-z0-9._~+/=-]{8,}/g

// The `(?<![\w-])` anchors (rather than `\b`) keep a match from starting inside a run of its own
// characters, which keeps these scans linear on long adversarial input.
const JWT = /(?<![\w-])eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*/g

const VENDOR_TOKENS: RegExp[] = [
  /(?<![\w-])(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, // AWS access key ids
  /(?<![\w-])gh[pousr]_[A-Za-z0-9]{36,}\b/g, // GitHub tokens
  /(?<![\w-])github_pat_[A-Za-z0-9_]{22,}/g, // GitHub fine-grained PATs
  /(?<![\w-])sk-ant-[A-Za-z0-9_-]{20,}/g, // Anthropic
  /(?<![\w-])sk-(?=[A-Za-z0-9_-]*[0-9A-Z])[A-Za-z0-9_-]{20,}/g, // OpenAI-style
  /(?<![\w-])xox[abposr]-[A-Za-z0-9-]{10,}/g, // Slack
]

/** `-H LM:NT` / `-H NT` / `-hashes [LM]:NT` (impacket, nxc). */
const HASH_FLAG =
  /(^|\s)(-H|-hashes|--hashes)(\s+)(['"]?)(?:[0-9a-fA-F]{32})?:?[0-9a-fA-F]{32}(?![0-9a-fA-F])/g
/** A bare `LM:NT` pair (secretsdump output and the like). */
const NTLM_PAIR = /\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b/g

/** curl-style `-u user:pass` / `--user user:pass` / `--proxy-user`; user kept. */
const USER_COLON = new RegExp(
  String.raw`(^|\s)(-u\s*|-U\s+|--user[=\s]\s*|--proxy-user[=\s]\s*)(?:'([^':]*):([^']*)'|"([^":]*):([^"]*)"|([^\s:'"]+):([^\s'"]+))`,
  'g',
)
/** smbclient / rpcclient `-U [DOMAIN/]user%pass`; user kept. */
const USER_PERCENT = /(^|\s)(-U\s*|--user(?:name)?[=\s]\s*)(['"]?)([^\s%'"]+)%([^\s'"]+)/g

/** `--password v`, `--pass=v`, `--token v`, `--api-key v`, `--client-secret v`, … */
const SECRET_FLAG = new RegExp(
  String.raw`(^|\s)(--(?:[\w-]*[-_])?(?:password|passwd|pass|pwd|token|secret|api-?key|apikey|access-?key|client-?secret))(=|\s+)(?!-)(${VALUE})`,
  'gi',
)

/** xfreerdp-style `/p:v` and `/pth:v`. */
const SLASH_P = new RegExp(String.raw`(^|\s)(/p:|/pth:)(${VALUE})`, 'g')

/** `-p v` / `-pV` — only where it means a password (see `redactPFlag`). */
const P_FLAG = new RegExp(String.raw`(^|\s)-p(?:(\s+)(?!-)|(?=[^\s-]))(${VALUE})`, 'g')
const USER_FLAG = /(^|\s)(?:-u|-U|--user|--username)(?=[\s=]|[^\s-])/
const CREDENTIAL_TOOL =
  /(^|[\s/])(?:sshpass|mysql|mysqldump|mariadb|hydra|medusa|nxc|netexec|crackmapexec|cme|evil-winrm|smbmap|kerbrute|mongo|mongosh|impacket-[\w-]+|[\w-]+\.py)(?=\s|$)/
/** Contexts where a scheme-less `[DOMAIN/]user:password@host` is a credential (impacket targets). */
const IMPACKET_CONTEXT =
  /(^|[\s/])(?:impacket-[\w-]+|[\w-]+\.py|nxc|netexec|crackmapexec|cme)(?=\s|$)/
const SCHEMELESS_USERINFO =
  /(^|[\s'"])((?:[\w.-]+\/)?[\w.$-]+):([^\s'"]+)@(?=[\w.-]+(?:[\s'":]|$))/g

/** `token=v`, `api_key: v`, `"password": "v"`, `AWS_SECRET_ACCESS_KEY=v`, query parameters, … */
const KV = new RegExp(
  String.raw`(^|[^\w.-])((?:[\w.-]*(?:password|passwd|passphrase|apikey|api[_-]key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token|access[_-]?token|refresh[_-]?token|session[_-]?token))|(?:[\w.-]*[_.-])?(?:token|secret|pass|pwd|sig|signature))(["']?\s*[=:]\s*)('[^']*'|"[^"]*"|[^\s&'",;}]+)`,
  'gi',
)

/** Keys whose string values in `data` are secrets whatever they contain. */
const SENSITIVE_KEY =
  /^(?:.*[_.-])?(?:password|passwd|passphrase|pwd|pass|token|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|authorization|cookie)$|(?:Password|Passwd|Token|Secret|ApiKey|AccessKey|PrivateKey|ClientSecret)$/i

/** Splits a command line at `&&`, `||`, `;`, `|` and newlines, keeping the separators. */
function segments(s: string): string[] {
  return s.split(/(&&|\|\||[;|\n])/)
}

/** `-p` means "password" only next to a user flag or in a credential-taking tool (not nmap/docker/mkdir). */
function redactPFlag(segment: string): string {
  if (!USER_FLAG.test(segment) && !CREDENTIAL_TOOL.test(segment)) return segment
  return segment.replace(P_FLAG, (_m, lead: string, space: string | undefined, value: string) =>
    value === REDACTED ? _m : `${lead}-p${space ?? ''}${mask(value)}`,
  )
}

function redactImpacketTarget(segment: string): string {
  if (!IMPACKET_CONTEXT.test(segment)) return segment
  return segment.replace(
    SCHEMELESS_USERINFO,
    (_m, lead: string, user: string) => `${lead}${user}:${REDACTED}@`,
  )
}

/** Redacts every secret pattern in `s` (see module comment). */
export function redact(s: string): string {
  let out = s.replace(
    PRIVATE_KEY,
    (_m, kind: string, block: string | undefined) =>
      `-----BEGIN ${kind}PRIVATE KEY${block ?? ''}-----\n${REDACTED}\n-----END ${kind}PRIVATE KEY${block ?? ''}-----`,
  )
  out = out.replace(
    URL_USERINFO,
    (_m, scheme: string, user: string) => `${scheme}${user}:${REDACTED}@`,
  )
  out = segments(out).map(redactImpacketTarget).join('')
  out = out.replace(
    HEADER,
    (_m, name: string, sep: string, quote: string, scheme: string | undefined) =>
      `${name}${sep}${quote}${scheme ?? ''}${REDACTED}`,
  )
  out = out.replace(
    AUTH_SCHEME,
    (_m, scheme: string, space: string) => `${scheme}${space}${REDACTED}`,
  )
  out = out.replace(JWT, REDACTED)
  for (const re of VENDOR_TOKENS) out = out.replace(re, REDACTED)
  out = out.replace(
    HASH_FLAG,
    (_m, lead: string, flag: string, space: string, quote: string) =>
      `${lead}${flag}${space}${quote}${REDACTED}`,
  )
  out = out.replace(NTLM_PAIR, REDACTED)
  out = out.replace(
    USER_COLON,
    (
      _m,
      lead: string,
      flag: string,
      sqUser: string | undefined,
      _sqPass: string | undefined,
      dqUser: string | undefined,
      _dqPass: string | undefined,
      user: string | undefined,
    ) => {
      if (sqUser !== undefined) return `${lead}${flag}'${sqUser}:${REDACTED}'`
      if (dqUser !== undefined) return `${lead}${flag}"${dqUser}:${REDACTED}"`
      return `${lead}${flag}${user}:${REDACTED}`
    },
  )
  out = out.replace(
    USER_PERCENT,
    (_m, lead: string, flag: string, quote: string, user: string) =>
      `${lead}${flag}${quote}${user}%${REDACTED}`,
  )
  out = out.replace(
    SECRET_FLAG,
    (_m, lead: string, flag: string, sep: string, value: string) =>
      `${lead}${flag}${sep}${mask(value)}`,
  )
  out = out.replace(
    SLASH_P,
    (_m, lead: string, flag: string, value: string) => `${lead}${flag}${mask(value)}`,
  )
  out = segments(out).map(redactPFlag).join('')
  out = out.replace(
    KV,
    (_m, lead: string, key: string, sep: string, value: string) =>
      `${lead}${key}${sep}${mask(value)}`,
  )
  return out
}

/**
 * `redact` applied to every string leaf of plain objects and arrays (a new value; the input is not
 * modified). A string under a credential-named key (`password`, `apiKey`, `client_secret`, …) is
 * replaced outright.
 */
export function redactDeep<T>(v: T): T {
  return deep(v, undefined) as T
}

/** An argv element whose next element is a secret. */
const ARGV_SECRET_FLAG =
  /^(?:--(?:[\w-]*[-_])?(?:password|passwd|pass|pwd|token|secret|api-?key|apikey|access-?key|client-?secret))$/i
const ARGV_USER_FLAG = /^(?:-u|-U|--user|--username|--proxy-user)$/
const ARGV_HASH_FLAG = /^(?:-H|-hashes|--hashes)$/
const NT_HASH_ARG = /^:?[0-9a-fA-F]{32}(?::[0-9a-fA-F]{32})?$/

/** An attached `-pVALUE` argv element. */
const ARGV_ATTACHED_P = /^-p(?=[^-])([\s\S]+)$/

/**
 * A string array is treated as argv: a flag's secret value may be a separate element, and the
 * context rules (`-p` meaning a password, impacket `user:pass@host` targets) are decided on the
 * whole command, not on the element alone.
 */
function redactArgv(argv: string[]): string[] {
  const joined = argv.join(' ')
  const pIsPassword = USER_FLAG.test(joined) || CREDENTIAL_TOOL.test(joined)
  const impacket = IMPACKET_CONTEXT.test(joined)
  return argv.map((arg, i) => {
    const flag = i > 0 ? (argv[i - 1] as string) : undefined
    if (flag !== undefined) {
      if (ARGV_SECRET_FLAG.test(flag) || (flag === '-p' && pIsPassword)) return REDACTED
      if (ARGV_HASH_FLAG.test(flag) && NT_HASH_ARG.test(arg)) return REDACTED
      if (ARGV_USER_FLAG.test(flag)) return redact(`${flag} ${arg}`).slice(flag.length + 1)
    }
    if (pIsPassword && ARGV_ATTACHED_P.test(arg)) return `-p${REDACTED}`
    let out = redact(arg)
    if (impacket) {
      out = out.replace(
        SCHEMELESS_USERINFO,
        (_m, lead: string, user: string) => `${lead}${user}:${REDACTED}@`,
      )
    }
    return out
  })
}

function deep(v: unknown, key: string | undefined): unknown {
  if (typeof v === 'string')
    return key !== undefined && SENSITIVE_KEY.test(key) ? REDACTED : redact(v)
  if (Array.isArray(v)) {
    if (v.length > 1 && v.every((x) => typeof x === 'string')) return redactArgv(v as string[])
    return v.map((x) => deep(x, undefined))
  }
  if (v !== null && typeof v === 'object') {
    const proto = Object.getPrototypeOf(v)
    if (proto !== Object.prototype && proto !== null) return v
    const out: Record<string, unknown> = {}
    for (const [k, x] of Object.entries(v)) out[k] = deep(x, k)
    return out
  }
  return v
}
