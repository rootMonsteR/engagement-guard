import { splitShellChain } from '../shell/chain.js'

/** Constructs whose effect cannot be known from the text alone; the guard asks instead of passing. */
export type OpaqueKind =
  | 'command-substitution'
  | 'backticks'
  | 'process-substitution'
  | 'eval'
  | 'xargs'
  | 'variable'
  | 'unbalanced-quote'
  | 'here-doc'
  | 'unreadable-target-file'
  | 'powershell'
  | 'unparseable-target'
  | 'unparseable-rate'
  | 'nested-command-unresolved'
  /** A shell or interpreter reads its program from a pipe, a redirect or stdin (final review C2). */
  | 'piped-code'
  /** An encoded PowerShell command, or inline code that decodes or executes data at run time. */
  | 'encoded-command'
  /** A script file written earlier in the same command is executed. */
  | 'script-written-here'

/** A redirection removed from `argv`: `op` is `>`, `>>`, `<`, `&>`, `>|`, `<>` … */
/**
 * A redirection removed from `argv`. `fd` is the explicit descriptor number written before the
 * operator (`2>`, `5<>`), absent when the default applies. A descriptor duplication (`2>&1`,
 * `<&5`, `>&-`) has op `>&` or `<&` and the source descriptor (or `-`) as its target.
 */
export interface Redirect {
  op: string
  target: string
  fd?: string
}

/** One segment of a command between core's chain operators, split into words. */
export interface Segment {
  index: number
  text: string
  argv: string[]
  operatorBefore: string | null
  opaque: OpaqueKind[]
  redirects: Redirect[]
}

const SUBSTITUTION_OPENERS: Readonly<Record<string, OpaqueKind>> = {
  '$(': 'command-substitution',
  '`': 'backticks',
  '<(': 'process-substitution',
  '>(': 'process-substitution',
}

const BLANK = /[ \t\r\n]/
const DIGITS = /^\d+$/
// `$NAME`, `${…}`, `$1`, `$@`, `$*`, `$#`, `$?`, `$$`, `$!`, `$-`, and `$'…'` / `$"…"` quoting.
const EXPANSION_START = /[A-Za-z_{0-9@*#?$!'"-]/

const addOpaque = (list: OpaqueKind[], kind: OpaqueKind) => {
  if (!list.includes(kind)) list.push(kind)
}

interface WordState {
  words: string[]
  opaque: OpaqueKind[]
  redirects: Redirect[]
}

/**
 * Reads one word starting at `i` (quotes, escapes, `$` expansions). Returns the word and the
 * index after it. A word stops at a blank, `(`, `)`, `<` or `>` outside quotes.
 */
function readWord(
  s: string,
  start: number,
  st: WordState,
): { word: string; end: number; quoted: boolean } {
  let word = ''
  let quoted = false
  let i = start
  while (i < s.length) {
    const ch = s[i] as string
    if (BLANK.test(ch) || ch === '(' || ch === ')' || ch === '<' || ch === '>') break
    if (ch === '&' && s[i + 1] === '>') break
    if (ch === "'") {
      const close = s.indexOf("'", i + 1)
      if (close < 0) {
        addOpaque(st.opaque, 'unbalanced-quote')
        word += s.slice(i + 1)
        return { word, end: s.length, quoted: true }
      }
      quoted = true
      word += s.slice(i + 1, close)
      i = close + 1
      continue
    }
    if (ch === '"') {
      i++
      quoted = true
      let closed = false
      while (i < s.length) {
        const c = s[i] as string
        if (c === '"') {
          closed = true
          i++
          break
        }
        if (c === '\\' && i + 1 < s.length && '"\\$`\n'.includes(s[i + 1] as string)) {
          word += s[i + 1]
          i += 2
          continue
        }
        if (c === '$' && EXPANSION_START.test(s[i + 1] ?? '')) addOpaque(st.opaque, 'variable')
        word += c
        i++
      }
      if (!closed) addOpaque(st.opaque, 'unbalanced-quote')
      continue
    }
    if (ch === '\\') {
      if (i + 1 < s.length) word += s[i + 1]
      i += 2
      continue
    }
    if (ch === '$' && EXPANSION_START.test(s[i + 1] ?? '')) addOpaque(st.opaque, 'variable')
    word += ch
    i++
  }
  return { word, end: i, quoted }
}

const skipBlanks = (s: string, i: number) => {
  let j = i
  while (j < s.length && BLANK.test(s[j] as string)) j++
  return j
}

/** Reads a redirection operator at `i` (`<`, `>`, `>>`, `<<`, `<<<`, `>&`, `&>`, `>|`, `<>` …). */
function readRedirect(s: string, i: number, st: WordState, fd: string | undefined): number {
  const m = /^(?:&>>?|<<<|<<-?|<>|>>|>\||>&|<&|>|<)/.exec(s.slice(i))
  const op = m?.[0] ?? (s[i] as string)
  let j = i + op.length
  if (op.startsWith('<<')) addOpaque(st.opaque, 'here-doc')
  const withFd = (r: Redirect): Redirect => (fd === undefined ? r : { ...r, fd })
  // `>&2`, `2>&1`, `>&-`, `<&0`: a descriptor duplication has no file target.
  if ((op === '>&' || op === '<&') && /^[\d-]/.test(s[j] ?? '')) {
    const from = j
    while (j < s.length && /[\d-]/.test(s[j] as string)) j++
    st.redirects.push(withFd({ op, target: s.slice(from, j) }))
    return j
  }
  j = skipBlanks(s, j)
  if (j >= s.length) return j
  const { word, end } = readWord(s, j, st)
  if (!op.startsWith('<<')) st.redirects.push(withFd({ op: op === '>&' ? '>' : op, target: word }))
  return end
}

/** POSIX-ish word splitting of one segment. Never throws. */
function splitWords(text: string): WordState {
  const st: WordState = { words: [], opaque: [], redirects: [] }
  let i = 0
  let fd: string | undefined
  while (i < text.length) {
    i = skipBlanks(text, i)
    if (i >= text.length) break
    const ch = text[i] as string
    if (ch === '#') break // comment to end of segment
    if (ch === '(' || ch === ')') {
      i++
      continue
    }
    if (ch === '<' || ch === '>' || (ch === '&' && text[i + 1] === '>')) {
      i = readRedirect(text, i, st, fd)
      fd = undefined
      continue
    }
    // readWord always consumes at least one character here, so the loop always advances.
    const { word, end, quoted } = readWord(text, i, st)
    i = end
    // `2>file`: an unquoted all-digit word directly followed by a redirection is a descriptor.
    const next = text[i]
    if ((next === '<' || next === '>') && !quoted && DIGITS.test(word)) {
      fd = word
      continue
    }
    if (word !== '' || quoted) st.words.push(word)
  }
  return st
}

/**
 * Splits `command` with core's `splitShellChain` (the only place chaining and substitution
 * operators are recognised) and word-splits each segment. Substitution openers (`$(`, a backtick,
 * `<(`, `>(`) mark the segment they open and its parent as opaque. Backslash-newline line
 * continuations are joined first. Never throws.
 */
export function tokenizeCommand(command: string): Segment[] {
  try {
    const joined = command.replace(/\\\r?\n/g, ' ')
    const chain = splitShellChain(joined)
    const segments: Segment[] = chain.segments.map((text, index) => {
      const st = splitWords(text)
      return {
        index,
        text,
        argv: st.words,
        operatorBefore: index === 0 ? null : (chain.operators[index - 1] ?? null),
        opaque: st.opaque,
        redirects: st.redirects,
      }
    })
    chain.operators.forEach((op, k) => {
      const kind = SUBSTITUTION_OPENERS[op]
      if (kind === undefined) return
      const opened = segments[k + 1]
      const parent = segments[k]
      if (opened) addOpaque(opened.opaque, kind)
      if (parent) addOpaque(parent.opaque, kind)
    })
    return segments
  } catch {
    return [
      {
        index: 0,
        text: command,
        argv: [],
        operatorBefore: null,
        opaque: ['unbalanced-quote'],
        redirects: [],
      },
    ]
  }
}

// --- wrappers -----------------------------------------------------------------------------------

/** Programs that run another program given as their arguments. */
export const WRAPPERS: ReadonlySet<string> = new Set([
  'sudo',
  'doas',
  'env',
  'nice',
  'ionice',
  'timeout',
  'time',
  'stdbuf',
  'nohup',
  'proxychains',
  'proxychains4',
  'torsocks',
  'command',
  'exec',
  'watch',
  'setsid',
])

interface WrapperOptions {
  /** Options that take a separate value (`--opt=value` and attached short values are handled). */
  value: ReadonlySet<string>
  /** Positional arguments before the wrapped program (timeout's duration). */
  positionals?: number
}

/** Options as documented in each wrapper's man page (sudo(8), env(1), timeout(1), …). */
const WRAPPER_OPTIONS: Readonly<Record<string, WrapperOptions>> = {
  sudo: {
    value: new Set([
      '-u',
      '--user',
      '-g',
      '--group',
      '-C',
      '--close-from',
      '-D',
      '--chdir',
      '-p',
      '--prompt',
      '-r',
      '--role',
      '-t',
      '--type',
      '-T',
      '--command-timeout',
      '-U',
      '--other-user',
      '-R',
      '--chroot',
    ]),
  },
  doas: { value: new Set(['-u', '-C']) },
  env: { value: new Set(['-u', '--unset', '-C', '--chdir', '-S', '--split-string']) },
  nice: { value: new Set(['-n', '--adjustment']) },
  ionice: {
    value: new Set([
      '-c',
      '--class',
      '-n',
      '--classdata',
      '-p',
      '--pid',
      '-P',
      '--pgid',
      '-u',
      '--uid',
    ]),
  },
  timeout: { value: new Set(['-s', '--signal', '-k', '--kill-after']), positionals: 1 },
  time: { value: new Set(['-f', '--format', '-o', '--output']) },
  stdbuf: { value: new Set(['-i', '--input', '-o', '--output', '-e', '--error']) },
  nohup: { value: new Set() },
  proxychains: { value: new Set(['-f']) },
  proxychains4: { value: new Set(['-f']) },
  torsocks: { value: new Set(['-u', '--user', '-p', '--pass', '-a', '--address', '-P', '--port']) },
  command: { value: new Set() },
  exec: { value: new Set(['-a']) },
  // procps-ng watch(1): -n/--interval SECONDS; a single remaining word is run through `sh -c`.
  watch: { value: new Set(['-n', '--interval']) },
  // util-linux setsid(1): -c/--ctty, -f/--fork, -w/--wait are switches.
  setsid: { value: new Set() },
}

/** Shell reserved words that may precede a command inside a compound statement. */
const RESERVED = new Set(['!', '{', '}', 'do', 'then', 'else', 'elif', 'if', 'while', 'until'])
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/

/** Basename without directories and a trailing `.exe`. */
export function programName(token: string): string {
  const base = token.split(/[\\/]/).pop() ?? token
  return base.replace(/\.exe$/i, '')
}

/** `command [-p] -v|-V name`: the options before the first non-option include -v or -V. */
function lookupOnly(argv: string[]): boolean {
  for (const tok of argv.slice(1)) {
    if (!/^-[pvV]+$/.test(tok)) return false
    if (/[vV]/.test(tok)) return true
  }
  return false
}

/**
 * Drops leading `VAR=value` assignments, shell reserved words and wrapper programs with their
 * options (`timeout 30`, `nice -n 5`, `sudo -u x`, `env -S "…"` is spliced in). Returns what is left
 * and the wrappers that were removed, in order, plus the dropped `VAR=value` words (their values
 * can name hosts: `DOCKER_HOST=tcp://h:2375`, `HTTPS_PROXY=…`).
 */
export function stripWrappers(argv: string[]): {
  argv: string[]
  wrappers: string[]
  assignments: string[]
} {
  let rest = [...argv]
  const wrappers: string[] = []
  const assignments: string[] = []
  let guard = 0
  while (rest.length > 0 && guard++ < 64) {
    const head = rest[0] as string
    if (ASSIGNMENT.test(head) || RESERVED.has(head)) {
      if (ASSIGNMENT.test(head)) assignments.push(head)
      rest = rest.slice(1)
      continue
    }
    const name = programName(head).toLowerCase()
    if (!WRAPPERS.has(name)) break
    // `command -v X` / `command -V X` only look X up; leave `command` as the (inert) program.
    if (name === 'command' && lookupOnly(rest)) break
    wrappers.push(name)
    const opts = WRAPPER_OPTIONS[name] ?? { value: new Set<string>() }
    let i = 1
    const spliced: string[] = []
    while (i < rest.length) {
      const tok = rest[i] as string
      if (tok === '--') {
        i++
        break
      }
      // `env -` is `env -i`; for every other wrapper a lone `-` is an argument.
      if (tok === '-' && name === 'env') {
        i++
        continue
      }
      if (!tok.startsWith('-') || tok === '-') break
      if (/^-\d+$/.test(tok)) {
        i++ // `nice -10`
        continue
      }
      const eq = tok.indexOf('=')
      const flag = tok.startsWith('--') && eq > 0 ? tok.slice(0, eq) : tok
      const isSplit = flag === '-S' || flag === '--split-string'
      if (tok.startsWith('--') && eq > 0) {
        if (name === 'env' && isSplit)
          spliced.push(
            ...tok
              .slice(eq + 1)
              .split(/\s+/)
              .filter(Boolean),
          )
        i++
      } else if (opts.value.has(tok)) {
        if (name === 'env' && isSplit) {
          spliced.push(...(rest[i + 1] ?? '').split(/\s+/).filter(Boolean))
        }
        i += 2
      } else if (!tok.startsWith('--') && tok.length > 2 && opts.value.has(tok.slice(0, 2))) {
        if (name === 'env' && tok.startsWith('-S'))
          spliced.push(...tok.slice(2).split(/\s+/).filter(Boolean))
        i++ // attached value: `-oL`, `-n5`
      } else {
        i++
      }
    }
    i += Math.min(opts.positionals ?? 0, Math.max(0, rest.length - i))
    rest = [...spliced, ...rest.slice(i)]
  }
  return { argv: rest, wrappers, assignments }
}
