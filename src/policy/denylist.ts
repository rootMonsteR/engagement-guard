import type { CommandAnalysis } from '../extract/extractor.js'
import { type IpRange, parseIpSpec } from '../scope/ip.js'
import {
  anyCommand,
  anyRemote,
  base,
  firstOperand,
  flagValues,
  lower,
  normPath,
  type SimpleCommand,
  viewsOf,
  walkAnalyses,
} from './command-views.js'

/**
 * A hard refusal (spec §6.5 row 1, §6.11). Checked on every Bash command, network or not, before
 * any case state: no case, mode, grant or setting turns a hit into anything but DENY `HARD_REFUSAL`.
 * `test` is pure and linear in the size of the analysis.
 */
export interface DenyEntry {
  id: string
  description: string
  test(a: CommandAnalysis): boolean
  /** A compliant alternative for a hit (`--script "vuln and not dos"`), when one exists. */
  suggest?(a: CommandAnalysis): string | null
}

// ---- dos-tools ----------------------------------------------------------------------------------

const DOS_PROGRAMS = new Set([
  'slowloris',
  'slowhttptest',
  't50',
  'thc-ssl-dos',
  'goldeneye',
  'hulk',
  'mdk3',
  'mdk4',
])

function isDosCommand(c: SimpleCommand): boolean {
  if (DOS_PROGRAMS.has(c.program)) return true
  if (c.program === 'hping3' || c.program === 'hping') {
    // hping3 accepts unambiguous long-option prefixes and single-dash long options.
    if (c.args.some((t) => /^--?flo(?:od?)?$/.test(t))) return true
    // `-i u<N>`: an interval in microseconds is a flood in all but name.
    return flagValues(c.args, ['-i', '--interval', '-interval'], true).some((v) =>
      v.startsWith('u'),
    )
  }
  if (c.program === 'aireplay-ng') {
    // `-0 <count>`, and `-00` (`-0 0`: deauthenticate continuously).
    return c.args.some((t) => /^-0\d*$/.test(t) || t === '--deauth' || t.startsWith('--deauth='))
  }
  return false
}

// ---- nmap-script-dos ----------------------------------------------------------------------------

/** NSE scripts in the `dos` category (nmap.org/nsedoc/categories/dos.html). */
const DOS_NSE = [
  'broadcast-avahi-dos',
  'http-slowloris',
  'ipv6-ra-flood',
  'smb-flood',
  'smb-vuln-conficker',
  'smb-vuln-cve2009-3103',
  'smb-vuln-ms06-025',
  'smb-vuln-ms07-029',
  'smb-vuln-ms08-067',
  'smb-vuln-ms10-054',
  'smb-vuln-regsvc-dos',
]
const DOS_NSE_SET = new Set(DOS_NSE)

/** Shell-style `*`/`?` match without regexes: greedy with single-star backtracking, O(n·m). */
function globMatch(pattern: string, text: string): boolean {
  let p = 0
  let t = 0
  let star = -1
  let mark = 0
  while (t < text.length) {
    const pc = pattern[p]
    if (pc !== undefined && (pc === '?' || pc === text[t])) {
      p++
      t++
    } else if (pc === '*') {
      star = p++
      mark = t
    } else if (star >= 0) {
      p = star + 1
      t = ++mark
    } else return false
  }
  while (pattern[p] === '*') p++
  return p === pattern.length
}

/** Categories that contain some `dos`-category scripts (nmap's `vuln` runs smb-vuln-ms08-067). */
const DOS_CARRYING = new Set(['vuln', 'exploit', 'intrusive', 'broadcast'])
/** Selectors that run every script, dos included. */
const SELECTS_ALL = new Set(['all', '*'])

const scriptWord = (word: string): string => {
  const w = word.toLowerCase()
  return base(w.startsWith('+') ? w.slice(1) : w).replace(/\.nse$/, '')
}

/** The word names a DoS script (directly or by a wildcard), not a category. */
function namesDosScript(w: string): boolean {
  if (w.includes('*') || w.includes('?')) return DOS_NSE.some((name) => globMatch(w, name))
  if (DOS_NSE_SET.has(w) || w.endsWith('-dos') || w.includes('flood')) return true
  return w.includes('slowloris') && !w.endsWith('-check')
}

/**
 * A directory runs every script in it: `./scripts/`, `/usr/share/nmap/scripts`, `.`. Failing
 * closed, any path that is not a `.nse` file counts as a directory (`/opt/my-nse`).
 */
function isScriptDirectory(raw: string): boolean {
  const p = normPath(raw)
  if (p.endsWith('/') || p === '.' || p === '..') return true
  if (p.slice(p.lastIndexOf('/') + 1) === 'scripts') return true
  return p.includes('/') && !p.endsWith('.nse')
}

/** Whether an arbitrary dos-category script is selected: never, for some, or always (Kleene logic). */
const NO = 0
const SOME = 1
const ALL = 2
type Tri = typeof NO | typeof SOME | typeof ALL

interface WordValue {
  value: Tri
  /** Names `dos`, a DoS script or a script directory: refused even inside `… and not dos`. */
  direct: boolean
}

function wordValue(raw: string): WordValue {
  // Some dos scripts, not exactly the dos set: `not ./scripts/` still selects dos scripts.
  if (isScriptDirectory(raw)) return { value: SOME, direct: true }
  const w = scriptWord(raw)
  if (w === 'dos') return { value: ALL, direct: true }
  if (SELECTS_ALL.has(w)) return { value: ALL, direct: false }
  if (DOS_CARRYING.has(w)) return { value: SOME, direct: false }
  if (w.includes('*') || w.includes('?')) {
    // A wildcard may match DoS script names, or (failing closed) a dos-carrying category name.
    const carrying = ['dos', ...DOS_CARRYING].some((name) => globMatch(w, name))
    return { value: carrying || namesDosScript(w) ? SOME : NO, direct: false }
  }
  if (namesDosScript(w)) return { value: SOME, direct: true }
  return { value: NO, direct: false }
}

interface ScriptElement {
  text: string
  value: Tri
  /** A DoS script or directory named outside a `not`. */
  direct: boolean
  /** The expression did not parse; it is refused. */
  unsure: boolean
}

const MAX_SCRIPT_NESTING = 32

/**
 * One comma element of a `--script` value, evaluated for an arbitrary dos-category script with
 * nmap's grammar (`or` < `and` < `not` < parentheses). Words: `dos`, `all` and `*` select every
 * dos script; vuln/exploit/intrusive/broadcast and DoS script names select some; other names and
 * categories select none. Anything that does not parse fails closed.
 */
function scriptElement(text: string): ScriptElement {
  const tokens = text
    .replace(/[()]/g, ' $& ')
    .split(/\s+/)
    .filter((t) => t !== '')
  const el: ScriptElement = { text: text.trim(), value: NO, direct: false, unsure: false }
  if (tokens.length === 0) return el
  let pos = 0
  const keyword = (k: string) => tokens[pos]?.toLowerCase() === k
  const fail = (): Tri => {
    el.unsure = true
    return ALL
  }
  const expr = (depth: number, negated: boolean): Tri => {
    let v = term(depth, negated)
    while (!el.unsure && keyword('or')) {
      pos++
      v = Math.max(v, term(depth, negated)) as Tri
    }
    return v
  }
  const term = (depth: number, negated: boolean): Tri => {
    let v = factor(depth, negated)
    while (!el.unsure && keyword('and')) {
      pos++
      v = Math.min(v, factor(depth, negated)) as Tri
    }
    return v
  }
  const factor = (depth: number, negated: boolean): Tri => {
    if (depth > MAX_SCRIPT_NESTING) return fail()
    const t = tokens[pos]
    if (t === undefined || t === ')' || keyword('and') || keyword('or')) return fail()
    pos++
    if (t.toLowerCase() === 'not') return (ALL - factor(depth + 1, !negated)) as Tri
    if (t === '(') {
      const v = expr(depth + 1, negated)
      if (tokens[pos] !== ')') return fail()
      pos++
      return v
    }
    const w = wordValue(t)
    if (w.direct && !negated) el.direct = true
    return w.value
  }
  const v = expr(0, false)
  if (!el.unsure && pos !== tokens.length) fail()
  el.value = el.unsure ? ALL : v
  return el
}

const runsDos = (el: ScriptElement): boolean => el.direct || el.unsure || el.value !== NO

/** `--script` values: `dos`, `"default,dos"`, `vuln`, `"not safe"`; `"vuln and not dos"` passes. */
const scriptValueRunsDos = (value: string): boolean =>
  value.split(',').some((part) => runsDos(scriptElement(part)))

const NSE_DIR_HINT = new Set(['scripts', 'nmap', 'nse'])

/**
 * A `--script` path that is one script file missing its `.nse` extension (`…/scripts/http-title`,
 * `~/nse/http-title`) — a bare path word, under a recognised NSE directory, that is not itself a DoS
 * script. Not a real directory (trailing `/`, a `scripts`/`.`/`..` leaf), a glob or an expression.
 */
function extensionlessScriptPath(raw: string): string | null {
  const t = raw.trim()
  if (t === '' || /[\s()*?]/.test(t)) return null
  const p = normPath(t)
  if (!p.includes('/') || p.endsWith('/') || p.endsWith('.nse')) return null
  const leaf = p.slice(p.lastIndexOf('/') + 1)
  if (leaf === '' || leaf === '.' || leaf === '..' || leaf === 'scripts') return null
  const ancestors = p.slice(0, p.lastIndexOf('/')).split('/')
  if (!ancestors.some((part) => NSE_DIR_HINT.has(part))) return null
  const asFile = `${t}.nse`
  return runsDos(scriptElement(asFile)) ? null : asFile
}

/**
 * The operator's own `--script` value with dos excluded, or `null` when nothing would be left.
 * Elements naming a DoS script or directory, or that do not parse, are dropped.
 */
function compliantScript(value: string): string | null {
  const parts: string[] = []
  for (const part of value.split(',')) {
    const el = scriptElement(part)
    if (el.text === '') continue
    if (el.direct || el.unsure) {
      // A directory fails closed, but an extensionless single-script path gets a `.nse` suggestion.
      const asFile = extensionlessScriptPath(el.text)
      if (asFile !== null) parts.push(asFile)
      continue
    }
    if (el.value === NO) parts.push(el.text)
    else parts.push(/[\s()]/.test(el.text) ? `(${el.text}) and not dos` : `${el.text} and not dos`)
  }
  return parts.length > 0 ? `--script "${parts.join(',')}"` : null
}

const nmapScriptValues = (c: SimpleCommand): string[] =>
  c.program === 'nmap' ? flagValues(c.args, ['--script', '-script']) : []

// ---- random-targeting ---------------------------------------------------------------------------

/** zmap/masscan flags whose value is an address that is not a target. */
const SCAN_NON_TARGET_VALUE = [
  '--exclude',
  '--excludefile',
  '-b',
  '--blocklist-file',
  '--blacklist-file',
  '-S',
  '--source-ip',
  '--adapter-ip',
  '--router-ip',
  '-G',
  '--gateway-mac',
  '--router-mac',
  '--adapter-mac',
]
/** Flags that name where the targets come from (a list file, a config file or a resumed scan). */
const SCAN_TARGET_SOURCE: ReadonlyMap<string, readonly string[]> = new Map([
  [
    'zmap',
    ['-I', '--list-of-ips-file', '-w', '--allowlist-file', '--whitelist-file', '-C', '--config'],
  ],
  // masscan's `-c` is its config file; zmap's `-c` is a cooldown time, not a source.
  ['masscan', ['-iL', '--includefile', '-c', '--conf', '--resume', '--range', '--ranges', '--dst']],
])
const SCAN_HELP = new Set(['-h', '--help', '-V', '--version'])

/** nmap/masscan short forms: `0/0`, `64/7`, `10.0/8` (nmap reads `0` as 0.0.0.0). */
const SHORT_V4_CIDR = /^\d+(?:\.\d+){0,3}\/(\d+)$/

const isAddressList = (t: string): boolean =>
  t
    .split(',')
    .every((part) => part !== '' && (parseIpSpec(part) !== undefined || SHORT_V4_CIDR.test(part)))

/** zmap scans the whole IPv4 internet when given no range; masscan's default is no safer. */
function scansWithoutRange(c: SimpleCommand): boolean {
  const sources = SCAN_TARGET_SOURCE.get(c.program)
  if (sources === undefined) return false
  if (c.args.some((t) => SCAN_HELP.has(t) || t.startsWith('--list-'))) return false
  for (let i = 0; i < c.args.length; i++) {
    const t = c.args[i] as string
    if (SCAN_NON_TARGET_VALUE.includes(t)) {
      i++
      continue
    }
    if (SCAN_NON_TARGET_VALUE.some((f) => t.startsWith(`${f}=`))) continue
    if (sources.some((f) => t === f || t.startsWith(`${f}=`))) return false
    // A `$VAR` or substitution may hold the range; the guard asks about the opaque construct.
    if (t.includes('$') || t.includes('`')) return false
    if (isAddressList(t)) return false
  }
  return true
}

function isRandomTargeting(c: SimpleCommand): boolean {
  if (c.program === 'nmap') return c.args.some((t) => /^--?iR(?:=.*|\d+)?$/.test(t))
  if (c.program === 'hping3' || c.program === 'hping')
    return c.args.some((t) => t === '--rand-dest' || t === '-rand-dest')
  return scansWithoutRange(c)
}

// ---- global-range -------------------------------------------------------------------------------

const V4_GLOBAL = 1n << 25n // a /7 or larger
const V6_GLOBAL = 1n << 125n // a /3 or larger (2000::/3 is all global unicast)

const isGlobalRange = (r: IpRange): boolean =>
  r.end - r.start + 1n >= (r.family === 4 ? V4_GLOBAL : V6_GLOBAL)

/** Scanners whose address arguments are always targets. */
const REMOTE_SCANNERS = new Set([
  'nmap',
  'masscan',
  'zmap',
  'naabu',
  'rustscan',
  'hping3',
  'hping',
  'fping',
  'nuclei',
  'httpx',
])

/** A scanner argument (`0.0.0.0/0`, `--range=0.0.0.0/0`, `0/0`, `a,b`) that is a global range. */
function isGlobalToken(token: string): boolean {
  const eq = token.startsWith('-') ? token.indexOf('=') : -1
  const value = eq >= 0 ? token.slice(eq + 1) : token
  return value.split(',').some((part) => {
    if (part === '') return false
    const r = parseIpSpec(part)
    if (r !== undefined) return isGlobalRange(r)
    const short = SHORT_V4_CIDR.exec(part)
    return short !== null && Number(short[1]) <= 7
  })
}

function targetsGlobalRange(a: CommandAnalysis): boolean {
  for (const an of walkAnalyses(a)) {
    for (const seg of an.segments) {
      if (seg.tier === null || seg.nonNetwork) continue
      for (const t of seg.targets) {
        // Swept literals are not targets of the tool (an ssh remote command's arguments, say).
        if (t.inert || t.provenance === 'literal') continue
        if (t.target.kind === 'range' && isGlobalRange(t.target.range)) return true
      }
    }
  }
  // Scanner address arguments, read from the tokens: covers pivot hosts (remote commands) and
  // scanners the extractor's table does not know.
  return anyCommand(a, (c) => REMOTE_SCANNERS.has(c.program) && c.args.some(isGlobalToken))
}

// ---- log-wipe -----------------------------------------------------------------------------------

const DELETERS = new Set([
  'shred',
  'truncate',
  'rm',
  'unlink',
  'srm',
  'wipe',
  'del',
  'erase',
  'remove-item',
  'ri',
  'clear-content',
  'clc',
])

function isLogPath(t: string): boolean {
  const p = normPath(t)
  return (
    p === '/var/log' ||
    p.startsWith('/var/log/') ||
    p.startsWith('/private/var/log/') ||
    p.includes('/winevt/logs')
  )
}

const PS_EVENTLOG_CMDLET = /\b(?:clear|remove)-eventlog\b/i
const PS_WEVTUTIL = /\bwevtutil(?:\.exe)?\b/i
const PS_CLEAR_LOG_VERB = /(?:^|\s)(?:cl|clear-log)(?=\s|$)/i
const PS_DELETER = /(?:^|[\s|{(;])(?:remove-item|del|erase|rm|ri)(?=[\s|});]|$)/

/** Commands that only document another command (`Get-Help Clear-EventLog`). */
const HELP_HEADS = new Set(['get-help', 'help', 'man', 'get-command', 'gcm'])
const PS_WORD = /^[\w-]+$/
/** Help switches that cannot capture the command object (unlike -OutVariable / -PipelineVariable). */
const HELP_SWITCHES_NOARG = new Set([
  '-full',
  '-detailed',
  '-examples',
  '-online',
  '-syntax',
  '-showwindow',
])
const HELP_SWITCHES_ARG = new Set(['-parameter', '-name'])
/** Constructs that can invoke a captured command object (the statement is then not a pure lookup). */
const PS_INVOKES = /[$&]|\.\(|\biex\b|\binvoke-|\bstart-process\b/i
/** Stages that only format, sort, count or display a pipeline — never invoke it. */
const PS_DISPLAY =
  /^\s*(?:more|out-string|out-host|out-null|format-\S+|sort-object|sort|measure-object)\b/i
const PS_SELECT = /^\s*(?:select-object|select)\b(.*)$/i

/**
 * Parameters a display cmdlet may carry and still only display. PowerShell accepts any unambiguous
 * prefix of a parameter name and any of the dash characters `- – — ―`, so a denylist of capturing
 * names (`-OutVariable`, `-ov`, `-pv`) would miss `-OutVar c` or `–ov c`: every dash-prefixed token
 * must be in this allowlist instead.
 */
const PS_DISPLAY_PARAMS = new Set([
  'property',
  'descending',
  'unique',
  'culture',
  'casesensitive',
  'top',
  'bottom',
  'stable',
  'autosize',
  'wrap',
  'groupby',
  'view',
  'force',
  'expand',
  'displayerror',
  'showerror',
  'hidetableheaders',
  'width',
  'stream',
  'nonewline',
  'paging',
  'inputobject',
  'sum',
  'average',
  'maximum',
  'minimum',
  'line',
  'word',
  'character',
  'ignorewhitespace',
  'allstats',
  'standarddeviation',
])
const PS_DASH_TOKEN = /(?:^|\s)[-–—―]([a-z][a-z0-9]*)(?=[\s:]|$)/gi

/** Every dash-prefixed token of a display stage names a display-only parameter. */
function displayParamsOnly(stage: string): boolean {
  for (const m of stage.matchAll(PS_DASH_TOKEN)) {
    if (!PS_DISPLAY_PARAMS.has((m[1] ?? '').toLowerCase())) return false
  }
  // A dash token the regex did not understand (`-ov:c`, `-$x`, `--x`) is not a display parameter.
  return !/(?:^|\s)[-–—―](?![a-z][a-z0-9]*(?:[\s:]|$))/i.test(stage)
}

/** A later pipeline stage that can only format or display the result (`select` with plain names). */
function isOutputOnlyStage(stage: string): boolean {
  if (stage.includes('$')) return false
  // Capturing parameters (`Sort-Object -OutVariable c; & $c[0] …`, `-OutVar`, `–ov`) make a
  // display cmdlet a capture, not a display: only allowlisted parameters keep it display-only.
  if (!displayParamsOnly(stage)) return false
  if (PS_DISPLAY.test(stage)) return true
  const m = PS_SELECT.exec(stage)
  // Select-Object is display-only only with plain property names — not -ExpandProperty, -First, etc.
  return m !== null && !/[-(){}&]/.test(m[1] ?? '')
}

/**
 * A stage that only documents a command: `<help> <name> [-Switch [value]]…`, where every switch is a
 * harmless help switch — never -OutVariable/-PipelineVariable or any other capturing switch — and the
 * stage has no `&`, `.`, `(` or `$`. Checked token by token, so it stays linear.
 */
function isHelpOnly(stage: string): boolean {
  const tokens = stage.trim().split(/\s+/)
  if (!HELP_HEADS.has(tokens[0]?.toLowerCase() ?? '') || !PS_WORD.test(tokens[1] ?? ''))
    return false
  let wantValue = false
  for (let i = 2; i < tokens.length; i++) {
    const t = tokens[i] as string
    const lc = t.toLowerCase()
    if (HELP_SWITCHES_NOARG.has(lc)) wantValue = false
    else if (HELP_SWITCHES_ARG.has(lc)) wantValue = true
    else if (wantValue && PS_WORD.test(t)) wantValue = false
    else return false
  }
  return true
}

/** A later stage of the pipeline does more than format or display the result (so it could invoke it). */
function pipelineInvokesResult(laterStages: string[]): boolean {
  return !laterStages.every(isOutputOnlyStage)
}

/** A statement or pipeline stage that clears or removes event logs; pure help lookups are exempt. */
function mentionsLogClearing(text: string): boolean {
  for (const statement of text.split(/[;\n]/)) {
    const stages = statement.split('|')
    for (let i = 0; i < stages.length; i++) {
      const stage = stages[i] as string
      const clears =
        PS_EVENTLOG_CMDLET.test(stage) || (PS_WEVTUTIL.test(stage) && PS_CLEAR_LOG_VERB.test(stage))
      if (!clears) continue
      // Positive allowlist: exempt a help lookup only when the whole statement can merely display the
      // result — nothing that could invoke it (`{`, `$`, `&`, `.(`, `iex`, `invoke-`) and every later
      // stage display-only. A capturing switch already made `isHelpOnly` false (round 4).
      const pureDisplay =
        isHelpOnly(stage) &&
        !statement.includes('{') &&
        !PS_INVOKES.test(statement) &&
        !pipelineInvokesResult(stages.slice(i + 1))
      if (pureDisplay) continue
      return true
    }
  }
  return false
}

/**
 * PowerShell text that clears event logs inside a pipeline or script block
 * (`Get-EventLog -List | % { Clear-EventLog $_.Log }`, `… winevt\Logs\*.evtx | Remove-Item`).
 */
function isPowerShellLogWipe(text: string): boolean {
  if (mentionsLogClearing(text)) return true
  for (const statement of normPath(text).split(/[;\n]/)) {
    if (statement.includes('/winevt/logs') && PS_DELETER.test(statement)) return true
  }
  return false
}

function isLogWipe(c: SimpleCommand): boolean {
  if (c.program === 'clear-eventlog' || c.program === 'remove-eventlog') return true
  if (c.truncates.some(isLogPath)) return true
  if (
    DELETERS.has(c.program) &&
    (c.args.some(isLogPath) || normPath(c.text).includes('/winevt/logs'))
  )
    return true
  if (c.program === 'find') {
    const root = firstOperand(c.args)
    if (root === undefined || !isLogPath(root)) return false
    const exec = c.args.indexOf('-exec')
    return (
      c.args.includes('-delete') ||
      (exec >= 0 && c.args.slice(exec + 1).some((t) => DELETERS.has(base(t))))
    )
  }
  if (c.program === 'wevtutil') {
    const sub = c.args[0]?.toLowerCase()
    if (sub === 'cl' || sub === 'clear-log') return true
    // `wevtutil sl <log> /e:false` disables the log.
    return (
      (sub === 'sl' || sub === 'set-log') &&
      lower(c.args).some((t) => /^\/e(?:nabled)?:false$/.test(t))
    )
  }
  return false
}

// ---- audit-disable ------------------------------------------------------------------------------

const unitName = (t: string) => t.toLowerCase().replace(/\.service$/, '')
const SERVICE_STOP = new Set(['stop', 'disable', 'mask', 'kill'])

/** `systemctl stop|disable|mask|kill <unit>`, `service <unit> stop`, `sc stop|config <unit>`, `Stop-Service`. */
function stopsService(c: SimpleCommand, units: ReadonlySet<string>): boolean {
  const args = lower(c.args)
  if (c.program === 'systemctl')
    return args.some((t) => SERVICE_STOP.has(t)) && args.some((t) => units.has(unitName(t)))
  if (c.program === 'service') return units.has(unitName(args[0] ?? '')) && args[1] === 'stop'
  if (c.program === 'sc')
    return (args[0] === 'stop' || args[0] === 'config') && units.has(unitName(args[1] ?? ''))
  if (c.program === 'stop-service' || c.program === 'spsv')
    return args.some((t) => units.has(unitName(t)))
  return false
}

const AUDIT_UNITS = new Set(['auditd'])

function isAuditDisable(c: SimpleCommand): boolean {
  if (c.program === 'auditctl') {
    if (c.args.includes('-D')) return true
    return flagValues(c.args, ['-e'], true).some((v) => v === '0')
  }
  if (c.program === 'auditpol') {
    return lower(c.args).some(
      (t) =>
        t === '/clear' ||
        t === '/remove' ||
        t.startsWith('/success:disable') ||
        t.startsWith('/failure:disable'),
    )
  }
  return stopsService(c, AUDIT_UNITS)
}

// ---- history-wipe (remote) ----------------------------------------------------------------------

const isHistoryFile = (t: string): boolean =>
  /_history(?:\.txt)?$/i.test(t) || /\.zhistory$/i.test(t)
const HIST_VAR = /^HIST(?:FILE=|(?:FILE)?SIZE=0$)/

function isHistoryWipe(c: SimpleCommand): boolean {
  if (c.assignments.some((t) => HIST_VAR.test(t))) return true
  switch (c.program) {
    case 'history':
      return c.args.some((t) => /^-[a-z]*c/.test(t))
    case 'unset':
      return c.args.includes('HISTFILE')
    case 'export':
    case 'declare':
    case 'typeset':
    case 'readonly':
      return c.args.some((t) => HIST_VAR.test(t))
    case 'set': {
      const o = c.args.indexOf('+o')
      return o >= 0 && c.args[o + 1] === 'history'
    }
    case 'clear-history':
    case 'clhy':
      return true
    case 'ln':
      return c.args.some(isHistoryFile)
  }
  if (c.truncates.some(isHistoryFile)) return true
  return DELETERS.has(c.program) && c.args.some(isHistoryFile)
}

// ---- timestomp ----------------------------------------------------------------------------------

const PS_TIME_PROPERTY = /^(?:creation|lastwrite|lastaccess)time(?:utc)?$/i
const PS_TIME_ASSIGN = /\.(?:creation|lastwrite|lastaccess)time(?:utc)?\s*=(?!=)/i

function isTimestompCommand(c: SimpleCommand): boolean {
  if (c.program === 'timestomp') return true
  if (c.program === 'msfconsole') return c.args.some((t) => /\btimestomp\b/i.test(t))
  if (c.program === 'set-itemproperty' || c.program === 'sp')
    return c.args.some((t) => PS_TIME_PROPERTY.test(t))
  // `touch -d/-t/-r` on a target backdates files; locally it is an ordinary build step.
  if (c.program === 'touch' && c.remote) {
    return c.args.some(
      (t) =>
        /^-[acmh]*[dtr]$/.test(t) ||
        t === '--date' ||
        t === '--reference' ||
        t.startsWith('--date=') ||
        t.startsWith('--reference='),
    )
  }
  return false
}

const isTimestomp = (a: CommandAnalysis): boolean =>
  anyCommand(a, isTimestompCommand) || viewsOf(a).powershell.some((s) => PS_TIME_ASSIGN.test(s))

// ---- remote-root-wipe ---------------------------------------------------------------------------

const ROOT_LIKE = new Set([
  '',
  '~',
  '$home',
  '${home}',
  '/home',
  '/root',
  '/etc',
  '/usr',
  '/bin',
  '/sbin',
  '/lib',
  '/boot',
  '/var',
  '/opt',
  '/srv',
])
const BLOCK_DEVICE = /^\/dev\/(?:sd|hd|vd|xvd|nvme|mmcblk|disk|md|dm-|mapper\/)/

/** `/`, `/*`, `~/`, `$HOME/.` … reduced to the directory they wipe. */
function wipedDir(t: string): string {
  let p = normPath(t)
  for (;;) {
    if (p.endsWith('/*')) p = p.slice(0, -2)
    else if (p.endsWith('/.')) p = p.slice(0, -2)
    else if (p.endsWith('/')) p = p.slice(0, -1)
    else return p
  }
}

function isRootWipe(c: SimpleCommand): boolean {
  if (c.program === 'rm') {
    if (c.args.includes('--no-preserve-root')) return true
    const recursive = c.args.some((t) => t === '--recursive' || /^-[A-Za-z]*[rR][A-Za-z]*$/.test(t))
    return recursive && c.args.some((t) => !t.startsWith('-') && ROOT_LIKE.has(wipedDir(t)))
  }
  if (c.program === 'dd')
    return c.args.some((t) => t.startsWith('of=') && BLOCK_DEVICE.test(t.slice(3)))
  if (c.program.startsWith('mkfs') || c.program === 'wipefs') return true
  if (DELETERS.has(c.program) && c.args.some((t) => BLOCK_DEVICE.test(t))) return true
  if (['remove-item', 'ri', 'rd', 'rmdir', 'del', 'erase'].includes(c.program)) {
    const args = lower(c.args)
    const recursive = args.some(
      (t) => t === '/s' || /^-r(?:e(?:c(?:u(?:r(?:s(?:e)?)?)?)?)?)?$/.test(t),
    )
    return recursive && args.some((t) => /^[a-z]:[\\/]?\*?$/.test(t))
  }
  if (c.program === 'format') return c.args.some((t) => /^[a-z]:$/i.test(t))
  return false
}

// ---- defence-disable (remote) -------------------------------------------------------------------

const DEFENCE_UNITS = new Set([
  'firewalld',
  'ufw',
  'iptables',
  'ip6tables',
  'nftables',
  'apparmor',
  'mpssvc',
  'windefend',
  'sense',
  'falcon-sensor',
  'wazuh-agent',
  'osqueryd',
  'elastic-agent',
])
const FALSE_VALUE = new Set(['false', '$false', '0'])

function isDefenceDisable(c: SimpleCommand): boolean {
  const args = lower(c.args)
  switch (c.program) {
    case 'netsh': {
      const j = ` ${args.join(' ')} `
      return (
        (j.includes(' advfirewall set ') && j.includes(' state off ')) ||
        (j.includes(' firewall set opmode ') &&
          (j.includes(' disable ') || j.includes('mode=disable')))
      )
    }
    case 'ufw':
      return firstOperand(args) === 'disable'
    case 'iptables':
    case 'ip6tables':
    case 'iptables-legacy':
    case 'iptables-nft':
    case 'ip6tables-legacy':
    case 'ip6tables-nft':
      return c.args.some((t) => t === '-F' || t === '--flush')
    case 'nft':
      return ` ${args.join(' ')} `.includes(' flush ruleset ')
    case 'set-mppreference':
      return args.some((t, i) => {
        const m = /^-disable[a-z]+(?::(.*))?$/.exec(t)
        if (!m) return false
        const value = m[1] ?? args[i + 1] ?? '$true'
        return !FALSE_VALUE.has(value)
      })
    case 'set-netfirewallprofile':
      return args.some((t, i) => {
        if (t === '-enabled') return FALSE_VALUE.has(args[i + 1] ?? '')
        const m = /^-enabled:(.*)$/.exec(t)
        return m !== null && FALSE_VALUE.has(m[1] as string)
      })
  }
  return stopsService(c, DEFENCE_UNITS)
}

// ---- the table ----------------------------------------------------------------------------------

/** The hard denylist, in the order `checkDenylist` reports hits. */
export const DENYLIST: readonly DenyEntry[] = [
  {
    id: 'dos-tools',
    description:
      'denial-of-service tools and flood modes (hping3 --flood or -i u<N>, slowloris, slowhttptest, t50, thc-ssl-dos, goldeneye, hulk, mdk3/mdk4, aireplay-ng --deauth)',
    test: (a) => anyCommand(a, isDosCommand),
  },
  {
    id: 'nmap-script-dos',
    description:
      'nmap --script that can run DoS scripts: the dos category, a dos/flood script, a script directory, or vuln/exploit/intrusive/broadcast/all/*/not <category> unless joined by "and not dos"',
    test: (a) => anyCommand(a, (c) => nmapScriptValues(c).some(scriptValueRunsDos)),
    suggest: (a) => {
      for (const c of viewsOf(a).commands) {
        const value = nmapScriptValues(c).find(scriptValueRunsDos)
        if (value !== undefined) return compliantScript(value)
      }
      return null
    },
  },
  {
    id: 'random-targeting',
    description:
      'random or unbounded targeting (nmap -iR, hping3 --rand-dest, zmap/masscan without an explicit range)',
    test: (a) => anyCommand(a, isRandomTargeting),
  },
  {
    id: 'global-range',
    description: 'internet-wide target ranges (0.0.0.0/0, IPv4 /1–/7, ::/0 and IPv6 /1–/3)',
    test: targetsGlobalRange,
  },
  {
    id: 'log-wipe',
    description:
      'log wiping (shred/truncate/rm on /var/log, wevtutil cl, Clear-EventLog, Remove-EventLog, deleting winevt logs)',
    test: (a) => anyCommand(a, isLogWipe) || viewsOf(a).powershell.some(isPowerShellLogWipe),
  },
  {
    id: 'audit-disable',
    description: 'disabling audit (auditctl -D, auditctl -e 0, stopping auditd, auditpol /clear)',
    test: (a) => anyCommand(a, isAuditDisable),
  },
  {
    id: 'history-wipe',
    description:
      'wiping shell history on a target (history -c, unset HISTFILE, deleting *_history in an ssh remote command)',
    test: (a) => anyRemote(a, isHistoryWipe),
  },
  {
    id: 'timestomp',
    description:
      'timestomping (timestomp, touch -d/-t/-r on a target, setting PowerShell CreationTime/LastWriteTime/LastAccessTime)',
    test: isTimestomp,
  },
  {
    id: 'remote-root-wipe',
    description:
      'wiping a target host (rm -rf / or ~, --no-preserve-root, dd/mkfs/shred on a disk, format, in a remote command)',
    test: (a) => anyRemote(a, isRootWipe),
  },
  {
    id: 'defence-disable',
    description:
      "disabling a target host's defences (netsh advfirewall … state off, ufw disable, iptables -F, stopping firewall/EDR services, Set-MpPreference -Disable…, in a remote command)",
    test: (a) => anyRemote(a, isDefenceDisable),
  },
]

/**
 * The first denylist entry `a` hits, or `undefined`. Results are memoised per analysis object
 * (a `WeakMap`), so never mutate a `CommandAnalysis` after checking it.
 */
export function checkDenylist(a: CommandAnalysis): DenyEntry | undefined {
  return DENYLIST.find((e) => e.test(a))
}
