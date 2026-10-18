import { containerForm } from './containers.js'
import { type OpaqueKind, programName } from './tokenizer.js'
import { type KnownToolSpec, lookupTool } from './tools-table.js'

/**
 * What the extractor must do for a program that runs another command: `eval`, `xargs`,
 * `find -exec`, `sh -c`, `su -c`, `script -c`, `pwsh -Command`, `cmd /c`, `docker run|exec|create`,
 * a single word holding a whole command (`watch "cmd"`), and interpreters running a known tool
 * (`python3 -m pip`, `python3 sqlmap.py`, `perl nikto.pl`).
 */
export interface SpecialForm {
  /** Opaque kinds the form adds to the segment. */
  opaque: OpaqueKind[]
  /** argv to parse with the program's own table entry, or `null` to skip that. */
  outer: string[] | null
  /** Analyse this argv as the segment's own tool (xargs). */
  inline?: { wrapper: string; argv: string[] }
  /** Analyse this text as a nested command. */
  nestedText?: { text: string; shell: 'posix' | 'powershell' }
  /** Analyse these argvs as one nested command, one segment each (find -exec clauses, docker run). */
  nestedArgvs?: string[][]
  /** Positional targets the form itself names (a container image's registry host). */
  targets?: string[]
  /** The interpreter runs a known tool: parse `argv` with `spec`. */
  script?: { spec: KnownToolSpec; argv: string[] }
}

const SHELL_NAMES: ReadonlySet<string> = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish'])
const PYTHON_NAMES: ReadonlySet<string> = new Set(['python', 'python3', 'python2', 'py', 'pypy3'])
const SCRIPT_RUNNERS: ReadonlySet<string> = new Set(['perl', 'ruby', 'php'])
const POWERSHELL_NAMES: ReadonlySet<string> = new Set(['pwsh', 'powershell'])
// util-linux su(1) / runuser(1) and script(1): `-c CMD`, `--command CMD`, `--command=CMD`.
const COMMAND_OPTION_PROGRAMS: ReadonlySet<string> = new Set(['su', 'script'])
const PWSH_COMMAND = /^[-/]c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?$/i
const FIND_EXEC: ReadonlySet<string> = new Set(['-exec', '-execdir', '-ok', '-okdir'])
// Heads that can begin a find expression (a continuation segment core split off at `;`): a primary
// (`-name`, `-exec`), a grouping/negation operator, or the `,` expression separator. Anything else
// (`su`, `script`, `runuser`, `docker-compose`, …) is a program and must not be read as a find clause.
const FIND_EXPR_HEADS: ReadonlySet<string> = new Set(['(', '\\(', ')', '\\)', '!', ','])
const isFindExprHead = (head: string): boolean => head.startsWith('-') || FIND_EXPR_HEADS.has(head)
const CONTAINER_RUNTIMES: ReadonlySet<string> = new Set(['docker', 'podman'])
const COMPOSE_PROGRAMS: ReadonlySet<string> = new Set(['docker-compose', 'podman-compose'])

// GNU findutils xargs(1) options that take a value.
const XARGS_VALUE: ReadonlySet<string> = new Set([
  '-a',
  '--arg-file',
  '-d',
  '--delimiter',
  '-E',
  '-I',
  '-L',
  '--max-lines',
  '-n',
  '--max-args',
  '-P',
  '--max-procs',
  '-s',
  '--max-chars',
  '--process-slot-var',
])

/** `sh -c 'cmd'` / `bash -lc 'cmd'`: the command string, or `undefined` for a script run. */
function shellCommand(argv: string[]): string | undefined {
  for (let i = 1; i < argv.length; i++) {
    const tok = argv[i] as string
    if (tok === '--') return undefined
    if (tok === '-o' || tok === '-O' || tok === '+o' || tok === '+O') {
      i++
      continue
    }
    if (/^-[A-Za-z]*c[A-Za-z]*$/.test(tok)) return argv[i + 1]
    if (!tok.startsWith('-') && !tok.startsWith('+')) return undefined
  }
  return undefined
}

/** `su -c CMD`, `script --command=CMD`, `script -qc CMD`. */
function commandOption(argv: string[]): string | undefined {
  for (let i = 1; i < argv.length; i++) {
    const tok = argv[i] as string
    if (tok.startsWith('--command=')) return tok.slice('--command='.length)
    if (tok === '--command' || /^-[A-Za-z]*c$/.test(tok)) return argv[i + 1]
  }
  return undefined
}

/**
 * Every `find … -exec|-execdir|-ok|-okdir ARGS ;|+` clause: the commands it runs. findutils ends a
 * clause at `;`, or at `+` only when it directly follows `{}`; any other `+` is an argument.
 */
function findExec(argv: string[]): string[][] {
  const out: string[][] = []
  let cur: string[] | null = null
  for (const tok of argv.slice(1)) {
    if (cur === null) {
      if (FIND_EXEC.has(tok)) cur = []
      continue
    }
    const ends = tok === ';' || tok === '\\;' || (tok === '+' && cur[cur.length - 1] === '{}')
    if (ends) {
      if (cur.length > 0) out.push(cur)
      cur = null
      continue
    }
    cur.push(tok)
  }
  if (cur !== null && cur.length > 0) out.push(cur)
  return out
}

// util-linux runuser(1) options.
const RUNUSER_VALUE: ReadonlySet<string> = new Set([
  '-c',
  '--command',
  '-g',
  '--group',
  '-G',
  '--supp-group',
  '-s',
  '--shell',
  '--session-command',
  '-u',
  '--user',
  '-w',
  '--whitelist-environment',
])
const RUNUSER_SWITCH: ReadonlySet<string> = new Set([
  '-f',
  '--fast',
  '-',
  '-l',
  '--login',
  '-m',
  '-p',
  '--preserve-environment',
  '-P',
  '--pty',
  '-T',
  '--no-pty',
  '-h',
  '--help',
  '-V',
  '--version',
])

type RunuserCommand = { text: string } | { argv: string[] } | 'unresolved' | undefined

/** A `-c`/`--command`/`--session-command` command string found among `tokens`, else `undefined`. */
function commandAfterDoubleDash(tokens: string[]): string | undefined {
  for (let k = 0; k < tokens.length; k++) {
    const tok = tokens[k] as string
    if (tok.startsWith('--command=')) return tok.slice('--command='.length)
    if (tok.startsWith('--session-command=')) return tok.slice('--session-command='.length)
    if (tok === '-c' || tok === '--command' || tok === '--session-command') {
      const value = tokens[k + 1]
      if (value !== undefined) return value
    }
  }
  return undefined
}

/**
 * `runuser [opts] -u USER [[--] CMD…]` runs CMD; `runuser [opts] [-] USER [ARGS…]` runs the user's
 * shell. runuser uses GNU getopt, which permutes, so options — including `-c`/`--command`/
 * `--session-command` — are still read after the user word, until a `--` ends option parsing.
 * Arguments after `--` are shell arguments: a `-c` command found among them is analysed, otherwise
 * the segment is opaque. An undocumented option makes the command unknown (`'unresolved'`).
 */
function runuserCommand(argv: string[]): RunuserCommand {
  let user = false
  let text: string | undefined
  // Non-option words seen before `-u`: getopt permutes, so `runuser nmap -u x -- -iR 10` runs
  // `nmap -iR 10` — they are command words once `-u` turns up.
  const leading: string[] = []
  let i = 1
  for (; i < argv.length; i++) {
    const tok = argv[i] as string
    if (tok === '--') {
      i++
      break
    }
    if (tok === '-') continue
    if (!tok.startsWith('-')) {
      // With `-u`, the first non-option word begins the command. Without it, the first word is the
      // user and the rest are shell arguments, but getopt still permutes options after them, so we
      // keep scanning for a `-c`/`--command`/`--session-command`.
      if (user) break
      leading.push(tok)
      continue
    }
    const eq = tok.indexOf('=')
    const name = tok.startsWith('--') && eq > 0 ? tok.slice(0, eq) : tok
    const inline = tok.startsWith('--') && eq > 0 ? tok.slice(eq + 1) : undefined
    if (RUNUSER_SWITCH.has(name)) continue
    if (!RUNUSER_VALUE.has(name)) return 'unresolved'
    const value = inline ?? argv[++i]
    if (name === '-u' || name === '--user') user = true
    if (name === '-c' || name === '--command' || name === '--session-command') text = value
  }
  if (text !== undefined) return { text }
  const rest = argv.slice(i)
  // With `-u`, the words after the options (or after `--`) — plus any permuted words seen before
  // `-u` — are the command itself.
  if (user) {
    const command = [...leading, ...rest]
    return command.length > 0 ? { argv: command } : undefined
  }
  // Without `-u`, only arguments after `--` remain unaccounted for: analyse a `-c` command there,
  // else fail closed so the guard asks about the shell arguments we cannot resolve.
  const after = commandAfterDoubleDash(rest)
  if (after !== undefined) return { text: after }
  return rest.length > 0 ? 'unresolved' : undefined
}

/** `python -m pip …`, `python3 sqlmap.py …`, `perl nikto.pl …`: the tool the interpreter runs. */
function scriptTool(
  lower: string,
  argv: string[],
  tools: readonly KnownToolSpec[],
): { spec: KnownToolSpec; argv: string[] } | undefined {
  const isPython = PYTHON_NAMES.has(lower)
  if (!isPython && !SCRIPT_RUNNERS.has(lower)) return undefined
  for (let i = 1; i < argv.length; i++) {
    const tok = argv[i] as string
    if (isPython && tok === '-m') {
      const mod = argv[i + 1]
      const spec = mod === undefined ? undefined : lookupTool(mod, tools)
      return spec && spec.category !== 'interpreter' ? { spec, argv: argv.slice(i + 1) } : undefined
    }
    if (tok === '-c' || tok === '-e' || tok === '-E' || tok === '-r') return undefined
    if (isPython && (tok === '-W' || tok === '-X')) {
      i++
      continue
    }
    if (tok.startsWith('-')) continue
    const spec = lookupTool(tok, tools)
    return spec && spec.category !== 'interpreter' ? { spec, argv: argv.slice(i) } : undefined
  }
  return undefined
}

/** The special form of `argv` (wrappers already stripped), or `undefined` for an ordinary program. */
export function specialForm(
  argv: string[],
  tools: readonly KnownToolSpec[],
): SpecialForm | undefined {
  const head = argv[0]
  if (head === undefined) return undefined
  // One word holding a whole command line (`watch "nmap x"`), unless it is a program path with a
  // blank in it (`"C:\Program Files\Nmap\nmap.exe"`).
  if (/\s/.test(head.trim()) && lookupTool(head, tools) === undefined) {
    return { opaque: [], outer: null, nestedText: { text: argv.join(' '), shell: 'posix' } }
  }
  const lower = programName(head).toLowerCase()
  if (lower === 'eval') {
    const text = argv.slice(1).join(' ')
    return { opaque: ['eval'], outer: null, nestedText: { text, shell: 'posix' } }
  }
  if (lower === 'xargs') {
    let i = 1
    while (i < argv.length && (argv[i] as string).startsWith('-')) {
      i += XARGS_VALUE.has(argv[i] as string) ? 2 : 1
    }
    const inline = { wrapper: 'xargs', argv: argv.slice(i) }
    return inline.argv.length > 0
      ? { opaque: ['xargs'], outer: null, inline }
      : { opaque: ['xargs'], outer: null }
  }
  // Core splits `find … -exec cmd {} \; -exec …` at the `;`, so a later clause arrives as its own
  // segment (`-exec …`, `\( -name x -exec …`, `, -exec …`): any segment containing an exec primary
  // whose first word is not a known program is a find continuation.
  if (
    lower !== 'find' &&
    isFindExprHead(head) &&
    argv.some((t) => FIND_EXEC.has(t)) &&
    !lookupTool(head, tools)
  ) {
    const clauses = findExec(['find', ...argv])
    return clauses.length > 0 ? { opaque: [], outer: null, nestedArgvs: clauses } : undefined
  }
  if (lower === 'find') {
    const clauses = findExec(argv)
    return clauses.length > 0 ? { opaque: [], outer: null, nestedArgvs: clauses } : undefined
  }
  if (SHELL_NAMES.has(lower)) {
    const body = shellCommand(argv)
    return body === undefined
      ? { opaque: [], outer: argv }
      : { opaque: [], outer: argv, nestedText: { text: body, shell: 'posix' } }
  }
  if (lower === 'runuser') {
    const command = runuserCommand(argv)
    if (command === undefined) return undefined
    if (command === 'unresolved') return { opaque: ['nested-command-unresolved'], outer: null }
    return 'text' in command
      ? { opaque: [], outer: null, nestedText: { text: command.text, shell: 'posix' } }
      : { opaque: [], outer: null, nestedArgvs: [command.argv] }
  }
  if (COMMAND_OPTION_PROGRAMS.has(lower)) {
    const body = commandOption(argv)
    return body === undefined
      ? undefined
      : { opaque: [], outer: null, nestedText: { text: body, shell: 'posix' } }
  }
  if (POWERSHELL_NAMES.has(lower)) {
    // `-EncodedCommand` cannot be read at all; the opaque flag makes the guard ask.
    const i = argv.findIndex((t, k) => k > 0 && PWSH_COMMAND.test(t))
    const text = i > 0 ? argv.slice(i + 1).join(' ') : undefined
    return text === undefined
      ? { opaque: ['powershell'], outer: argv }
      : { opaque: ['powershell'], outer: argv, nestedText: { text, shell: 'powershell' } }
  }
  if (lower === 'cmd') {
    const i = argv.findIndex((t, k) => k > 0 && /^\/[ck]$/i.test(t))
    return i > 0
      ? {
          opaque: [],
          outer: argv,
          nestedText: { text: argv.slice(i + 1).join(' '), shell: 'posix' },
        }
      : { opaque: [], outer: argv }
  }
  if (CONTAINER_RUNTIMES.has(lower) || COMPOSE_PROGRAMS.has(lower)) {
    const c = containerForm(argv, tools)
    return c && { opaque: c.opaque, outer: c.outer, nestedArgvs: c.nestedArgvs, targets: c.targets }
  }
  const script = scriptTool(lower, argv, tools)
  return script ? { opaque: [], outer: null, script } : undefined
}
