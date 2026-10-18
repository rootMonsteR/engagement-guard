import type { CommandAnalysis, SegmentAnalysis } from '../extract/extractor.js'

/**
 * Command views for the denylist: every simple command a `CommandAnalysis` runs, locally and on
 * remote hosts, normalised so a deny rule only looks at a program name and its arguments.
 */

/** One simple command, local (a segment of the analysis) or run on a remote host. */
export interface SimpleCommand {
  /**
   * Lower-cased basename without `.exe` (`/usr/sbin/hping3` → `hping3`, `Clear-EventLog` →
   * `clear-eventlog`); `''` for a bare redirection or assignment (`> /var/log/wtmp`, `HISTFILE=`).
   */
  program: string
  args: string[]
  /** Targets of truncating output redirects (`>`, `>|`, `&>`). */
  truncates: string[]
  /** Leading `NAME=value` assignments. */
  assignments: string[]
  /** Run on another host: an ssh remote command, or nxc/crackmapexec `-x`/`-X`. */
  remote: boolean
  /** The source text (local segments only; the tokenizer drops PowerShell's `\` path separators). */
  text: string
}

export interface Views {
  commands: SimpleCommand[]
  /** PowerShell source text (powershell analyses and remote `-X` / `pwsh -c` commands). */
  powershell: string[]
}

const MAX_REMOTE_DEPTH = 4
/** Nested ssh hops followed inside a remote command. */
const MAX_SSH_HOPS = 3
const TRUNCATING = new Set(['>', '>|', '&>', '1>', '2>'])
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'busybox'])
const POWERSHELLS = new Set(['pwsh', 'powershell'])
const INTERPRETERS = new Set(['python', 'python2', 'python3', 'py', 'perl', 'ruby', 'php'])
const SCRIPT_EXT = /\.(?:py|pl|rb|php|sh)$/i
/** Wrappers stripped from remote commands; local segments are stripped by the extractor. */
const PLAIN_WRAPPERS = new Set([
  'nohup',
  'exec',
  'command',
  'builtin',
  'time',
  'stdbuf',
  'then',
  'do',
])
const OPTION_WRAPPERS = new Set(['sudo', 'doas', 'env', 'nice', 'ionice', 'timeout'])
const SUDO_VALUE = new Set(['-u', '-g', '-U', '-C', '-h', '-p', '-r', '-t', '-D', '-n'])
/** sshpass(1) options that take a value. */
const SSHPASS_VALUE = new Set(['-p', '-f', '-d', '-P'])
const NXC_NAMES = new Set(['nxc', 'netexec', 'crackmapexec', 'cme'])
/** ssh options that take a value (OpenSSH ssh(1)). */
const SSH_VALUE_LETTERS = new Set('BbcDEeFIiJLlmOoPpQRSWw')

/** Basename of a program token, lower-cased, without `.exe`. */
export function base(token: string): string {
  const slash = Math.max(token.lastIndexOf('/'), token.lastIndexOf('\\'))
  const name = slash >= 0 ? token.slice(slash + 1) : token
  return name.replace(/\.exe$/i, '').toLowerCase()
}

/** Paths compared case-insensitively with `/` separators and no repeated slashes. */
export const normPath = (t: string): string =>
  t.replace(/\\/g, '/').replace(/\/+/g, '/').toLowerCase()

export const lower = (args: string[]): string[] => args.map((t) => t.toLowerCase())
export const firstOperand = (args: string[]): string | undefined =>
  args.find((t) => !t.startsWith('-'))

/** The value of each `name` (`-i x`, `--interval=x`, and `-ix` when `attachedShort`). */
export function flagValues(
  args: string[],
  names: readonly string[],
  attachedShort = false,
): string[] {
  const out: string[] = []
  for (let i = 0; i < args.length; i++) {
    const t = args[i] as string
    for (const n of names) {
      if (t === n) {
        const v = args[i + 1]
        if (v !== undefined) out.push(v)
      } else if (t.startsWith(`${n}=`)) out.push(t.slice(n.length + 1))
      else if (attachedShort && n.length === 2 && t.startsWith(n) && !t.startsWith('--'))
        out.push(t.slice(2))
    }
  }
  return out
}

export function* walkAnalyses(a: CommandAnalysis): Generator<CommandAnalysis> {
  yield a
  for (const s of a.segments) if (s.nested) yield* walkAnalyses(s.nested)
}

/** `sshpass -p pw ssh …` → `ssh …`. */
function viaSshpass(cmd: SimpleCommand): SimpleCommand {
  if (cmd.program !== 'sshpass') return cmd
  for (let i = 0; i < cmd.args.length; i++) {
    const t = cmd.args[i] as string
    if (t === '--') {
      const next = cmd.args[i + 1]
      return next === undefined ? cmd : { ...cmd, program: base(next), args: cmd.args.slice(i + 2) }
    }
    if (SSHPASS_VALUE.has(t)) {
      i++
      continue
    }
    if (t.startsWith('-')) continue // `-e`, `-v`, attached `-ppassword`
    return { ...cmd, program: base(t), args: cmd.args.slice(i + 1) }
  }
  return cmd
}

/** `python3 slowloris.py x` → program `slowloris`, args `[x]`. */
function viaInterpreter(cmd: SimpleCommand): SimpleCommand {
  if (!INTERPRETERS.has(cmd.program)) return cmd
  const i = cmd.args.findIndex((t) => !t.startsWith('-'))
  const script = i >= 0 ? (cmd.args[i] as string) : undefined
  if (script === undefined || !SCRIPT_EXT.test(script)) return cmd
  return { ...cmd, program: base(script).replace(SCRIPT_EXT, ''), args: cmd.args.slice(i + 1) }
}

const normalise = (cmd: SimpleCommand): SimpleCommand => viaInterpreter(viaSshpass(cmd))

function localCommand(seg: SegmentAnalysis): SimpleCommand | undefined {
  const truncates = seg.redirects.filter((r) => TRUNCATING.has(r.op)).map((r) => r.target)
  if (seg.program === null) {
    // A bare redirection (`> /var/log/auth.log`) truncates without a program.
    if (truncates.length === 0) return undefined
    return { program: '', args: [], truncates, assignments: [], remote: false, text: seg.text }
  }
  const program = base(seg.program)
  const k = seg.argv.findIndex((t) => base(t) === program)
  const at = k >= 0 ? k : 0
  return normalise({
    program: program.replace(SCRIPT_EXT, ''),
    args: seg.argv.slice(at + 1),
    truncates,
    assignments: seg.argv.slice(0, at).filter((t) => ASSIGNMENT.test(t)),
    remote: false,
    text: seg.text,
  })
}

/**
 * The command ssh runs on the remote host, or `undefined` for an interactive login. OpenSSH parses
 * options again after the destination (`ssh host -p 2222 cmd`) until `--` or the first operand.
 */
export function sshRemoteCommand(args: string[]): string | undefined {
  let haveDestination = false
  for (let i = 0; i < args.length; i++) {
    const tok = args[i] as string
    if (tok === '--') {
      const rest = args.slice(haveDestination ? i + 1 : i + 2)
      return rest.length > 0 ? rest.join(' ') : undefined
    }
    if (tok.startsWith('-') && tok.length > 1) {
      for (let j = 1; j < tok.length; j++) {
        if (SSH_VALUE_LETTERS.has(tok[j] as string)) {
          if (j === tok.length - 1) i++
          break
        }
      }
      continue
    }
    if (!haveDestination) {
      haveDestination = true
      continue
    }
    return args.slice(i).join(' ')
  }
  return undefined
}

/** Splits remote shell text into simple commands. Quotes are dropped; the split is conservative. */
function parseRemote(text: string, views: Views, depth: number): void {
  // `>|` truncates; keep the pipe split below from cutting it in two.
  for (const piece of text.replace(/>\|/g, '> ').split(/[;&|\n]+/)) {
    const words = piece.replace(/["']/g, '').split(/\s+/)
    const tokens: string[] = []
    const truncates: string[] = []
    for (let i = 0; i < words.length; i++) {
      const w = words[i] as string
      if (w === '') continue
      if (TRUNCATING.has(w)) {
        const target = words[i + 1]
        if (target !== undefined) truncates.push(target)
        i++
        continue
      }
      if (w === '>>' || w === '<' || w === '2>&1') {
        if (w !== '2>&1') i++
        continue
      }
      const redirect = /^(?:[12&])?(>>?|>\|)(.*)$/.exec(w)
      if (redirect) {
        if (redirect[1] !== '>>' && redirect[2] !== '') truncates.push(redirect[2] as string)
        continue
      }
      tokens.push(w)
    }
    const assignments: string[] = []
    let i = 0
    while (i < tokens.length) {
      const t = tokens[i] as string
      if (ASSIGNMENT.test(t)) {
        assignments.push(t)
        i++
        continue
      }
      const name = base(t)
      if (PLAIN_WRAPPERS.has(name)) {
        i++
        continue
      }
      if (OPTION_WRAPPERS.has(name)) {
        i++
        while (i < tokens.length) {
          const o = tokens[i] as string
          if (o.startsWith('-')) i += SUDO_VALUE.has(o) && name !== 'env' ? 2 : 1
          else if (ASSIGNMENT.test(o)) i++
          else if (name === 'timeout' && /^\d/.test(o)) i++
          else break
        }
        continue
      }
      break
    }
    const head = tokens[i]
    if (head === undefined) {
      if (assignments.length > 0 || truncates.length > 0) {
        const bare = { program: '', args: [], truncates, assignments, remote: true, text: '' }
        views.commands.push(bare)
      }
      continue
    }
    const program = base(head)
    const args = tokens.slice(i + 1)
    if (depth < MAX_REMOTE_DEPTH) {
      if (SHELLS.has(program)) {
        const c = args.findIndex((t) => /^-[A-Za-z]*c[A-Za-z]*$/.test(t))
        if (c >= 0) {
          parseRemote(args.slice(c + 1).join(' '), views, depth + 1)
          continue
        }
      }
      if (POWERSHELLS.has(program)) {
        const c = args.findIndex((t) => /^[-/]c(?:ommand)?$/i.test(t))
        if (c >= 0) {
          const body = args.slice(c + 1).join(' ')
          views.powershell.push(body)
          parseRemote(body, views, depth + 1)
          continue
        }
      }
      if (program === 'cmd') {
        const c = args.findIndex((t) => /^\/[ck]$/i.test(t))
        if (c >= 0) {
          parseRemote(args.slice(c + 1).join(' '), views, depth + 1)
          continue
        }
      }
    }
    const cmd = normalise({ program, args, truncates, assignments, remote: true, text: '' })
    views.commands.push(cmd)
    // A hop: `ssh pivot 'ssh root@h "history -c"'` runs the inner command on `h`.
    if (cmd.program === 'ssh' && depth < MAX_SSH_HOPS) {
      const inner = sshRemoteCommand(cmd.args)
      if (inner !== undefined) parseRemote(inner, views, depth + 1)
    }
  }
}

type QuoteState = null | "'" | '"' | "$'"

/**
 * The quote open at the end of `text`, starting from `state`: `'` ends only at `'`; inside `"`
 * and inside ANSI-C `$'…'` a backslash escapes the next character (so `$'\''` stays open);
 * outside quotes a backslash escapes the next character. Linear and total.
 *
 * Needed only because core's `splitShellChain` is not quote-aware, so `ssh h 'id; history -c'`
 * reaches the extractor as two segments. Delete this (and the carry in `viewsOf`) once the
 * splitter keeps quoted operators inside one segment.
 */
function scanQuotes(text: string, state: QuoteState): QuoteState {
  let open = state
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (open === "'") {
      if (ch === "'") open = null
      continue
    }
    if (ch === '\\') {
      i++
      continue
    }
    if (open === "$'") {
      if (ch === "'") open = null
      continue
    }
    if (open === '"') {
      if (ch === '"') open = null
      continue
    }
    if (ch === '$' && text[i + 1] === '$') {
      i++ // `$$` is the shell's PID; a `'` after it opens a plain single quote
    } else if (ch === '$' && text[i + 1] === "'") {
      open = "$'"
      i++
    } else if (ch === "'" || ch === '"') open = ch
  }
  return open
}

/** The remote commands an ssh or nxc/crackmapexec command runs, as source texts. */
function remoteTexts(cmd: SimpleCommand, views: Views): string[] {
  if (cmd.program === 'ssh') {
    const remote = sshRemoteCommand(cmd.args)
    return remote === undefined ? [] : [remote]
  }
  if (!NXC_NAMES.has(cmd.program)) return []
  const out: string[] = []
  for (let i = 0; i < cmd.args.length - 1; i++) {
    const flag = cmd.args[i]
    if (flag !== '-x' && flag !== '-X') continue
    const body = cmd.args[i + 1] as string
    if (flag === '-X') views.powershell.push(body)
    out.push(body)
  }
  return out
}

const PS_COMMAND_FLAG = /^[-/]c(?:ommand)?$/i
const PS_RUNNER = /\b(?:pwsh|powershell)(?:\.exe)?\s/i
const PS_FLAG_IN_TEXT = /(?:^|\s)[-/]c(?:ommand)?\s+/i
const NXC_PS_FLAG_IN_TEXT = /(?:^|\s)-X\s+/

/**
 * The PowerShell body a segment opens, without the runner and the opening quote: local
 * `pwsh -c '…`, `powershell -Command "…`, nxc/crackmapexec `-X '…`, or a remote command that runs
 * `pwsh -c` (`ssh h "pwsh -c '…`). `undefined` when the segment runs no PowerShell.
 */
function powerShellBody(cmd: SimpleCommand, remote: string[], text: string): string | undefined {
  let flag: RegExp | undefined
  if (POWERSHELLS.has(cmd.program) && cmd.args.some((t) => PS_COMMAND_FLAG.test(t)))
    flag = PS_FLAG_IN_TEXT
  else if (NXC_NAMES.has(cmd.program) && cmd.args.includes('-X')) flag = NXC_PS_FLAG_IN_TEXT
  else if (remote.some((r) => PS_RUNNER.test(`${r} `))) flag = PS_FLAG_IN_TEXT
  if (flag === undefined) return undefined
  const runner = flag === PS_FLAG_IN_TEXT ? PS_RUNNER.exec(text) : null
  const from = runner ? runner.index : 0
  const m = flag.exec(text.slice(from))
  if (!m) return text
  const body = text.slice(from + m.index + m[0].length)
  return body.replace(/^(?:\$'|['"])/, '')
}

const NXC_RUNNER = /\b(?:nxc|netexec|crackmapexec|cme)\b/i
/** Quote-openers (besides shells and remote scanners) whose body a `pwsh -c` continuation may join. */
const CARRY_EXTRA = new Set(['su', 'runuser', 'script', 'evil-winrm'])

/**
 * The PowerShell body a continuation segment opens, when a `pwsh -c` / `powershell -Command` or an
 * nxc/crackmapexec `-X` begins partway through an already-open quote (after another remote statement,
 * e.g. `ssh h "id; pwsh -c '…`). `undefined` when the segment runs no PowerShell.
 */
function powerShellBodyInText(text: string): string | undefined {
  if (PS_RUNNER.test(`${text} `)) {
    const runner = PS_RUNNER.exec(text)
    const from = runner ? runner.index : 0
    const m = PS_FLAG_IN_TEXT.exec(text.slice(from))
    if (m) return text.slice(from + m.index + m[0].length).replace(/^(?:\$'|['"])/, '')
  }
  if (NXC_RUNNER.test(text)) {
    const m = NXC_PS_FLAG_IN_TEXT.exec(text)
    if (m) return text.slice(m.index + m[0].length).replace(/^(?:\$'|['"])/, '')
  }
  return undefined
}

/** Drops the closing quote of a rebuilt PowerShell body (`… | more'`). */
const closeBody = (body: string): string => body.trimEnd().replace(/['"]+$/, '')

const bareTruncate = (target: string, remote: boolean, text: string): SimpleCommand => ({
  program: '',
  args: [],
  truncates: [target],
  assignments: [],
  remote,
  text,
})

/** Views of one analysis: its segments plus every nested analysis (no segment is ever skipped). */
function addSegments(an: CommandAnalysis, views: Views): void {
  let quote: QuoteState = null
  let remoteOpen = false
  // The quote-opener runs a subshell/remote host, so a `pwsh -c` continuation inside it is real.
  let carryBodyOpen = false
  let endsWithGt = false
  // A PowerShell body that the chain split cut at `|` or `;`, rebuilt from its segments.
  let psBody: string | null = null
  for (const seg of an.segments) {
    // Every segment keeps its local view and nested analysis — even one that looks like the inside
    // of a string literal. The quote scanner is a best-effort model of the shell (no `#` comments,
    // heredocs, `$(…)` re-quoting or PowerShell escapes), so treating "string content" as inert
    // would silently switch the denylist off whenever it falls out of step. The cost is a
    // fail-closed over-block such as `git commit -m "…; pwsh -c '…'"` until core splits quote-aware.
    const cmd = localCommand(seg)
    if (cmd) views.commands.push(cmd)
    if (seg.nested) addAnalysis(seg.nested, views)
    // `cmd >| file` is split at the `|`: the next segment's first word is the truncated file.
    const first = seg.argv[0]
    const truncated = endsWithGt && seg.operatorBefore === '|' ? first : undefined
    endsWithGt = seg.text.trimEnd().endsWith('>')
    if (quote !== null) {
      // The rest of a quoted word that the chain split cut; it belongs to the segment that opened it.
      if (remoteOpen) {
        if (truncated !== undefined) views.commands.push(bareTruncate(truncated, true, ''))
        parseRemote(seg.text, views, 0)
      }
      if (psBody !== null) psBody += `${seg.operatorBefore ?? ' '}${seg.text}`
      // A `pwsh -c` / nxc -X that starts partway through the open quote opens its own body here — but
      // only when a subshell/remote opened the quote, so `git commit -m "…; pwsh -c '…'"` is not caught.
      else if (carryBodyOpen) psBody = powerShellBodyInText(seg.text) ?? null
      quote = scanQuotes(seg.text, quote)
      if (quote === null) {
        remoteOpen = false
        carryBodyOpen = false
        if (psBody !== null) views.powershell.push(closeBody(psBody))
        psBody = null
      }
      continue
    }
    if (truncated !== undefined) views.commands.push(bareTruncate(truncated, false, seg.text))
    const remote = cmd ? remoteTexts(cmd, views) : []
    for (const text of remote) parseRemote(text, views, 0)
    quote = scanQuotes(seg.text, null)
    remoteOpen = quote !== null && remote.length > 0
    carryBodyOpen =
      quote !== null &&
      cmd !== undefined &&
      (remote.length > 0 ||
        SHELLS.has(cmd.program) ||
        POWERSHELLS.has(cmd.program) ||
        CARRY_EXTRA.has(cmd.program))
    if (quote !== null && cmd) psBody = powerShellBody(cmd, remote, seg.text) ?? null
  }
  if (psBody !== null) views.powershell.push(closeBody(psBody))
}

const VIEWS = new WeakMap<CommandAnalysis, Views>()

/**
 * Every simple command the analysis runs, locally and on remote hosts, plus its PowerShell texts.
 * Memoised per analysis object: callers must never mutate a `CommandAnalysis` after checking it.
 */
export function viewsOf(a: CommandAnalysis): Views {
  const cached = VIEWS.get(a)
  if (cached) return cached
  const views: Views = { commands: [], powershell: [] }
  addAnalysis(a, views)
  VIEWS.set(a, views)
  return views
}

/** One analysis: its PowerShell text (when a PowerShell shell) and its segments. */
function addAnalysis(an: CommandAnalysis, views: Views): void {
  if (an.shell === 'powershell') views.powershell.push(an.command)
  addSegments(an, views)
}

export const anyCommand = (a: CommandAnalysis, pred: (c: SimpleCommand) => boolean): boolean =>
  viewsOf(a).commands.some(pred)

export const anyRemote = (a: CommandAnalysis, pred: (c: SimpleCommand) => boolean): boolean =>
  viewsOf(a).commands.some((c) => c.remote && pred(c))
