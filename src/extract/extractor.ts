import { resolve } from 'node:path'
import type { Tier } from '../policy/decisions.js'
import { type IpRange, parseIpSpec } from '../scope/ip.js'
import type { Target } from '../scope/target.js'
import {
  AUTH_HEADER,
  buildIndex,
  deviceTargets,
  embeddedTargets,
  type FlagIndex,
  listParts,
  matchFlag,
  mergeSpec,
  parseTargetToken,
  remoteToken,
  TIER_RANK,
} from './args.js'
import { createListFileReader } from './list-file.js'
import { sweepLiterals } from './literals.js'
import { addRate, type RateFlags } from './rate.js'
import { specialForm } from './special-forms.js'
import {
  type OpaqueKind,
  programName,
  type Redirect,
  type Segment,
  stripWrappers,
  tokenizeCommand,
} from './tokenizer.js'
import { KNOWN_TOOLS, type KnownToolSpec, lookupTool, type ToolCategory } from './tools-table.js'

export interface ExtractedTarget {
  raw: string
  target: Target
  provenance: 'flag' | 'positional' | 'file' | 'literal'
  segment: number
  /** The flag (`-u`) or file (`targets.txt`) the target came from; `null` for positionals and literals. */
  source: string | null
  /** Found in a program that does not use the network (grep, echo, `git commit`, `nmap --version`). */
  inert: boolean
  /**
   * P16: `target` is what the action is aimed at; `infra` is contacted infrastructure (a resolver,
   * proxy or bind/source address given to the tool). Decoys, spoofed sources, idle-scan zombies and
   * FTP-bounce relays are targets.
   */
  role: 'target' | 'infra'
}

export interface SegmentAnalysis extends Segment {
  program: string | null
  wrappers: string[]
  tool: KnownToolSpec | null
  category: ToolCategory | null
  tier: Tier | 'dos' | null
  intrusive: boolean
  credentials: boolean
  hardDeny: string | null
  nonNetwork: boolean
  rate: RateFlags
  targets: ExtractedTarget[]
  excludes: IpRange[]
  /** Tokens in a target position that did not parse (each also adds opaque `unparseable-target`). */
  unparseable: string[]
  /** The command run by `sh -c`, `eval`, `find -exec`, `docker run`, … analysed on its own. */
  nested: CommandAnalysis | null
  /** A known network tool ran, or the shell itself opened a `/dev/tcp`-style connection. */
  knownNetwork: boolean
}

export interface CommandAnalysis {
  command: string
  segments: SegmentAnalysis[]
  targets: ExtractedTarget[]
  opaque: OpaqueKind[]
  knownNetwork: boolean
  tiers: (Tier | 'dos')[]
  hardDeny: string | null
  shell: 'posix' | 'powershell'
}

export interface ExtractContext {
  cwd: string
  shell: 'posix' | 'powershell'
}

export interface TargetExtractor {
  analyze(command: string, ctx: ExtractContext): Promise<CommandAnalysis>
}

export interface TargetExtractorOptions {
  tools?: readonly KnownToolSpec[]
  /**
   * Reads a target-list file. The default (`createListFileReader`) resolves symlinks, refuses
   * /proc, /sys and /dev and anything that is not a regular file, and reads at most
   * `maxTargetFileBytes + 1` bytes.
   */
  readFile?: (absPath: string) => Promise<string>
  maxTargetFileBytes?: number
}

const DEFAULT_MAX_TARGET_FILE_BYTES = 1024 * 1024
const MAX_DEPTH = 4
const OUTPUT_REDIRECTS: ReadonlySet<string> = new Set(['>', '>>', '>|', '&>', '&>>', '<>'])
// A value that names a list file: a path, a list extension, or (checked separately) a readable file.
const LIST_FILE_SHAPE = /[\\/]|\.(?:txt|lst|list|dic|dict|wordlist|csv)$/i

/** PowerShell networking cmdlets and their aliases (Microsoft.PowerShell.Utility, NetTCPIP, DnsClient, BitsTransfer, remoting). */
const PS_NETWORK_COMMANDS: ReadonlySet<string> = new Set([
  'invoke-webrequest',
  'iwr',
  'invoke-restmethod',
  'irm',
  'test-netconnection',
  'tnc',
  'test-connection',
  'resolve-dnsname',
  'start-bitstransfer',
  'new-pssession',
  'enter-pssession',
  'invoke-command',
  'icm',
  'send-mailmessage',
  'wget',
  'curl',
])
const PS_NETWORK_TEXT =
  /net\.webclient|net\.sockets|net\.http|downloadstring|downloadfile|webclient/i

const PROVENANCE_RANK: Readonly<Record<ExtractedTarget['provenance'], number>> = {
  flag: 0,
  positional: 1,
  file: 2,
  literal: 3,
}

const addOpaque = (list: OpaqueKind[], kind: OpaqueKind) => {
  if (!list.includes(kind)) list.push(kind)
}

function emptyAnalysis(seg: Segment): SegmentAnalysis {
  return {
    ...seg,
    argv: [...seg.argv],
    opaque: [...seg.opaque],
    redirects: [...seg.redirects],
    program: null,
    wrappers: [],
    tool: null,
    category: null,
    tier: null,
    intrusive: false,
    credentials: false,
    hardDeny: null,
    nonNetwork: false,
    rate: { raw: [] },
    targets: [],
    excludes: [],
    unparseable: [],
    nested: null,
    knownNetwork: false,
  }
}

/** Literals in programs that never touch the network are inert. Interpreters are never inert. */
const isInert = (s: SegmentAnalysis) =>
  s.nonNetwork ||
  s.category === 'inert' ||
  (s.tool !== null && s.tier === null && s.category !== 'interpreter')

function pickTarget(a: ExtractedTarget, b: ExtractedTarget): ExtractedTarget {
  const better =
    a.inert !== b.inert
      ? a.inert
        ? b
        : a
      : PROVENANCE_RANK[b.provenance] < PROVENANCE_RANK[a.provenance]
        ? b
        : a
  const role = a.role === 'target' || b.role === 'target' ? 'target' : 'infra'
  return { ...better, inert: a.inert && b.inert, role }
}

function dedupeTargets(list: ExtractedTarget[]): ExtractedTarget[] {
  const byRaw = new Map<string, ExtractedTarget>()
  for (const t of list) {
    const prev = byRaw.get(t.raw)
    byRaw.set(t.raw, prev ? pickTarget(prev, t) : t)
  }
  return [...byRaw.values()]
}

function listEntries(content: string): string[] {
  const out: string[] = []
  for (const line of content.split(/\r?\n/)) {
    const text = line.replace(/(?:^|\s)#.*$/, '').trim()
    if (text !== '') out.push(...text.split(/\s+/))
  }
  return out
}

// ---- interactive shells on a socket (P20) --------------------------------------------------------

const SOCKET_SHELLS: ReadonlySet<string> = new Set(['bash', 'sh', 'zsh', 'dash', 'ksh'])
const isDeviceTarget = (t: ExtractedTarget) => t.source === '/dev/tcp' || t.source === '/inet'
const isDeviceRedirect = (r: Redirect) => deviceTargets(r.target).length > 0
const isSocketShell = (s: SegmentAnalysis) =>
  s.program !== null && SOCKET_SHELLS.has(s.program.toLowerCase())

/** The descriptor stdin is duplicated from (`<&5`, `0<&5`, `0>&1`), if any. */
function stdinSource(r: Redirect): string | undefined {
  if (r.op === '<&') return (r.fd ?? '0') === '0' ? r.target : undefined
  if (r.op === '>&') return r.fd === '0' ? r.target : undefined
  return undefined
}

/** Descriptors opened on a `/dev/tcp`-style path by any segment (`exec 5<>/dev/tcp/…`, `>& /dev/tcp/…`). */
function socketFds(analyses: SegmentAnalysis[]): Set<string> {
  const fds = new Set<string>()
  for (const s of analyses) {
    for (const r of s.redirects) {
      if (isDeviceRedirect(r)) fds.add(r.fd ?? (r.op.startsWith('<') ? '0' : '1'))
    }
  }
  return fds
}

/**
 * P20: a `/dev/tcp`/`/dev/udp` connection is post-exploitation when a shell is wired to it — the
 * shell runs with `-i` on its own socket redirect, or reads stdin from the socket (`bash <
 * /dev/tcp/…`, `0>&1`, `<&196`); socket data is piped into a shell or a `while read` loop
 * (`cat <&5 | sh`); or a command's stdout and stderr are both sent back into the socket
 * (`$l 2>&5 >&5`). Plain probes (`echo > /dev/tcp/h/80`, `cat <&3`) stay recon.
 */
function socketShell(analyses: SegmentAnalysis[]): boolean {
  const fds = socketFds(analyses)
  if (fds.size === 0) return false
  const readsSocket = (s: SegmentAnalysis) =>
    s.redirects.some((r) => {
      if (r.op === '<' && isDeviceRedirect(r)) return true
      const src = stdinSource(r)
      return src !== undefined && fds.has(src)
    })
  return analyses.some((s, i) => {
    const interactive = s.argv.some((t) => /^-[A-Za-z]*i[A-Za-z]*$/.test(t))
    if (
      isSocketShell(s) &&
      ((interactive && s.redirects.some(isDeviceRedirect)) || readsSocket(s))
    ) {
      return true
    }
    const next = analyses[i + 1]
    if (
      readsSocket(s) &&
      next?.operatorBefore === '|' &&
      (isSocketShell(next) || next.argv[0] === 'while')
    ) {
      return true
    }
    const sendsBack = (fd: string) =>
      s.redirects.some((r) => r.op === '>&' && (r.fd ?? '1') === fd && fds.has(r.target))
    return sendsBack('1') && sendsBack('2')
  })
}

/** Per-segment state: argv positions kept out of the literal sweep, dropped `VAR=value` words. */
interface SegState {
  skip: Set<number>
  assignments: string[]
}

/**
 * Positions (in the segment's argv) of `child`, a suffix or an in-order subsequence of `parent`
 * whose positions are `pos`; `null` when unknown (then nothing is skipped, which only sweeps more).
 */
function subPositions(parent: string[], pos: number[] | null, child: string[]): number[] | null {
  if (pos === null) return null
  const off = parent.length - child.length
  if (off >= 0 && child.every((t, k) => parent[off + k] === t)) return pos.slice(off)
  const out: number[] = []
  let j = 0
  for (const t of child) {
    while (j < parent.length && parent[j] !== t) j++
    if (j >= parent.length) return null
    out.push(pos[j] as number)
    j++
  }
  return out
}

const isDirect = (t: ExtractedTarget) => t.provenance !== 'literal'

interface Run extends ExtractContext {
  depth: number
  written: Set<string>
}

/**
 * Creates the extractor. `readFile` (default: a bounded regular-file reader) reads `-iL`-style target
 * files relative to `ctx.cwd`.
 */
export function createTargetExtractor(opts: TargetExtractorOptions = {}): TargetExtractor {
  const tools = opts.tools ?? KNOWN_TOOLS
  const max = opts.maxTargetFileBytes ?? DEFAULT_MAX_TARGET_FILE_BYTES
  const readFile = opts.readFile ?? createListFileReader(max)

  /** File contents, or `undefined` when unreadable, too large, or written by this command. */
  async function readListFile(path: string, ctx: Run): Promise<string | undefined> {
    const abs = resolve(ctx.cwd, path)
    if (ctx.written.has(abs)) return undefined
    try {
      const content = await readFile(abs)
      return Buffer.byteLength(content, 'utf8') > max ? undefined : content
    } catch {
      return undefined
    }
  }

  async function analyzeCommand(command: string, ctx: Run): Promise<CommandAnalysis> {
    return analyzeSegments(command, tokenizeCommand(command), ctx)
  }

  async function analyzeSegments(
    command: string,
    segments: Segment[],
    ctx: Run,
  ): Promise<CommandAnalysis> {
    const written = new Set(ctx.written)
    for (const seg of segments) {
      for (const r of seg.redirects) {
        if (OUTPUT_REDIRECTS.has(r.op)) written.add(resolve(ctx.cwd, r.target))
      }
      if (seg.argv[0] !== undefined && programName(seg.argv[0]) === 'tee') {
        for (const a of seg.argv.slice(1)) if (!a.startsWith('-')) written.add(resolve(ctx.cwd, a))
      }
    }
    const run: Run = { ...ctx, written }
    const analyses: SegmentAnalysis[] = []
    for (const seg of segments) analyses.push(await analyzeSegment(seg, run))
    if (socketShell(analyses)) {
      for (const s of analyses) {
        if (s.targets.some(isDeviceTarget) || s.redirects.some(isDeviceRedirect)) {
          s.tier = 'post-exploitation'
        }
      }
    }
    if (ctx.shell === 'powershell') for (const s of analyses) addOpaque(s.opaque, 'powershell')

    const targets: ExtractedTarget[] = []
    const opaque: OpaqueKind[] = []
    const tiers: (Tier | 'dos')[] = []
    let hardDeny: string | null = null
    let knownNetwork = false
    for (const s of analyses) {
      targets.push(...s.targets)
      for (const k of s.opaque) addOpaque(opaque, k)
      if (s.knownNetwork) {
        knownNetwork = true
        if (s.tier !== null && !tiers.includes(s.tier)) tiers.push(s.tier)
      }
      hardDeny ??= s.hardDeny
      const n = s.nested
      if (n) {
        targets.push(...n.targets.map((t) => ({ ...t, segment: s.index })))
        for (const k of n.opaque) addOpaque(opaque, k)
        for (const t of n.tiers) if (!tiers.includes(t)) tiers.push(t)
        knownNetwork ||= n.knownNetwork
        hardDeny ??= n.hardDeny
      }
    }
    if (ctx.shell === 'powershell') {
      addOpaque(opaque, 'powershell')
      knownNetwork ||= analyses.some((s) => s.argv.some((tok) => namesNetworkCommand(tok)))
    }
    return {
      command,
      segments: analyses,
      targets: dedupeTargets(targets),
      opaque,
      knownNetwork,
      tiers,
      hardDeny,
      shell: ctx.shell,
    }
  }

  function namesNetworkCommand(tok: string): boolean {
    const name = programName(tok).toLowerCase()
    if (PS_NETWORK_COMMANDS.has(name) || PS_NETWORK_TEXT.test(tok)) return true
    const spec = lookupTool(name, tools)
    return spec !== undefined && spec.tier !== null
  }

  async function analyzeSegment(seg: Segment, ctx: Run): Promise<SegmentAnalysis> {
    const sa = emptyAnalysis(seg)
    const st: SegState = { skip: new Set(), assignments: [] }
    await analyzeArgv(
      sa,
      seg.argv,
      ctx,
      st,
      seg.argv.map((_, k) => k),
    )
    // Inertness only ever applies to free literal-sweep hits; flag, positional and file targets
    // were placed by the tool's own syntax and are always live.
    const inert = isInert(sa)
    const known = new Set(sa.targets.map((t) => t.raw))
    // P23: values of dropped `VAR=value` words (DOCKER_HOST, HTTPS_PROXY …) are live literals.
    const live = new Set(
      sweepLiterals(st.assignments.map((a) => a.slice(a.indexOf('=') + 1))).map((h) => h.raw),
    )
    const redirectTargets = seg.redirects.map((r) => r.target)
    const sweepTokens = [...seg.argv.filter((_, k) => !st.skip.has(k)), ...redirectTargets]
    for (const hit of sweepLiterals(sweepTokens, { attachedShort: sa.tool === null })) {
      if (known.has(hit.raw)) continue
      known.add(hit.raw)
      sa.targets.push({
        ...hit,
        provenance: 'literal',
        segment: seg.index,
        source: null,
        inert: inert && !live.has(hit.raw),
        role: 'target',
      })
    }
    // The shell itself connects for `/dev/tcp/host/port` (bash) and `/inet/tcp/…` (gawk) paths,
    // whatever the program is: those targets are never inert and the segment is network.
    let device = false
    for (const tok of [...seg.argv, ...redirectTargets]) {
      for (const hit of deviceTargets(tok)) {
        device = true
        const parsed = parseTargetToken(hit.raw)
        if (parsed === 'skip' || parsed === undefined) {
          if (!sa.unparseable.includes(hit.raw)) sa.unparseable.push(hit.raw)
          addOpaque(sa.opaque, 'unparseable-target')
          continue
        }
        sa.targets.push({
          raw: parsed.raw,
          target: parsed.target,
          provenance: 'literal',
          segment: seg.index,
          source: tok.includes('/inet') ? '/inet' : '/dev/tcp',
          inert: false,
          role: 'target',
        })
      }
    }
    sa.targets = dedupeTargets(sa.targets)
    // A known tool that was given a destination by its own syntax or its environment is a network
    // action even when its (sub)command is otherwise local (`docker -H tcp://h:2375 ps`,
    // `DOCKER_HOST=tcp://h:2375 docker ps`).
    const liveTarget = (t: ExtractedTarget) => isDirect(t) || live.has(t.raw)
    if (sa.tool !== null && sa.tier === null && !sa.nonNetwork && sa.targets.some(liveTarget)) {
      sa.tier = 'recon'
    }
    if (device && sa.tier === null) sa.tier = 'recon'
    sa.knownNetwork = device || (sa.tool !== null && !sa.nonNetwork && sa.tier !== null)
    return sa
  }

  const HIDDEN_SHELLS: ReadonlySet<string> = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish'])
  const HIDDEN_PWSH: ReadonlySet<string> = new Set(['pwsh', 'powershell'])
  /** Flags after which the next word is inline code, per interpreter family. */
  const INLINE_CODE_FLAGS: Readonly<Record<string, readonly string[]>> = {
    python: ['-c'],
    node: ['-e', '--eval', '-p', '--print'],
    perl: ['-e', '-E'],
    php: ['-r'],
  }
  const PWSH_ENCODED = /^[-/](?:e|ec|enc|encodedcommand)$/i
  const PWSH_COMMAND_FLAG = /^[-/]c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?$/i
  /** Inline code that decodes or executes data at run time cannot be read as a command line. */
  const CODE_EXEC =
    /(?:^|[^A-Za-z0-9_])(?:exec|eval|execSync|execFileSync|spawn|spawnSync|system|popen|subprocess|child_process|Invoke-Expression|iex)(?:$|[^A-Za-z0-9_])|b64decode|base64|unhexlify|fromhex|Buffer\.from/i

  function inlineFamily(lower: string): string | undefined {
    if (lower.startsWith('python') || lower === 'py' || lower === 'pypy3') return 'python'
    if (lower === 'node' || lower === 'nodejs') return 'node'
    if (lower === 'perl' || lower === 'ruby' || lower === 'lua') return 'perl'
    if (lower === 'php') return 'php'
    return undefined
  }

  /**
   * Final review C2: code an interpreter runs that the command text does not show. A shell or
   * interpreter whose program arrives through a pipe, a `<` redirect or `-s`/`-`; a PowerShell
   * `-EncodedCommand`; inline code that decodes or executes data at run time; and a script file
   * written earlier in the same command. Each marks the segment opaque, which the guard asks about.
   */
  function markHiddenCode(
    sa: SegmentAnalysis,
    name: string,
    rest: string[],
    spec: KnownToolSpec,
    ctx: Run,
  ): void {
    const lower = name.toLowerCase()
    const args = rest.slice(1)
    const shell = HIDDEN_SHELLS.has(lower)
    const pwsh = HIDDEN_PWSH.has(lower)
    const family = inlineFamily(lower)
    const codeFlags = family === undefined ? [] : (INLINE_CODE_FLAGS[family] ?? [])
    const valueFlags = new Set([...(spec.valueFlags ?? []), ...codeFlags])
    const inline: string[] = []
    let script: string | undefined
    let stdinScript = false
    for (let i = 0; i < args.length; i++) {
      const a = args[i] as string
      if (a === '--') {
        script ??= args[i + 1]
        break
      }
      if (pwsh && PWSH_ENCODED.test(a)) {
        addOpaque(sa.opaque, 'encoded-command')
        continue
      }
      if (pwsh && PWSH_COMMAND_FLAG.test(a)) {
        inline.push(args.slice(i + 1).join(' '))
        break
      }
      if (shell && /^-[A-Za-z]*c[A-Za-z]*$/.test(a)) {
        inline.push(args[i + 1] ?? '')
        break
      }
      if (shell && /^-[A-Za-z]*s[A-Za-z]*$/.test(a)) stdinScript = true
      if (a === '-') {
        stdinScript = true
        continue
      }
      if (a.startsWith('--') && a.includes('=')) {
        const eq = a.indexOf('=')
        if (codeFlags.includes(a.slice(0, eq))) inline.push(a.slice(eq + 1))
        continue
      }
      if (a.startsWith('-') && a !== '-') {
        if (codeFlags.includes(a)) {
          inline.push(args[i + 1] ?? '')
          i++
        } else if (valueFlags.has(a)) {
          i++
        }
        continue
      }
      script = a
      break
    }
    if (inline.some((code) => CODE_EXEC.test(code))) addOpaque(sa.opaque, 'encoded-command')
    const fromStdin = sa.operatorBefore === '|' || sa.redirects.some((r) => r.op === '<')
    if (stdinScript || (inline.length === 0 && script === undefined && fromStdin)) {
      addOpaque(sa.opaque, 'piped-code')
    }
    if (script !== undefined && ctx.written.has(resolve(ctx.cwd, script))) {
      addOpaque(sa.opaque, 'script-written-here')
    }
  }

  /** Adds a target the tool's syntax names; an unparseable one in a target position asks. */
  function addTargetTo(
    sa: SegmentAnalysis,
    tok: string,
    provenance: ExtractedTarget['provenance'],
    source: string | null,
    role: ExtractedTarget['role'] = 'target',
  ): void {
    if (tok.includes('$') && sa.opaque.includes('variable')) return
    const parsed = parseTargetToken(tok)
    if (parsed === 'skip') return
    if (parsed === undefined) {
      // Infrastructure we cannot read is not a scope target; only target positions ask.
      if (role === 'infra') return
      if (!sa.unparseable.includes(tok)) sa.unparseable.push(tok)
      addOpaque(sa.opaque, 'unparseable-target')
      return
    }
    if (parsed.credentials) sa.credentials = true
    sa.targets.push({
      raw: parsed.raw,
      target: parsed.target,
      provenance,
      segment: sa.index,
      source,
      inert: false,
      role,
    })
  }

  async function nestedText(
    sa: SegmentAnalysis,
    text: string,
    ctx: Run,
    shell: ExtractContext['shell'],
  ) {
    if (ctx.depth >= MAX_DEPTH) {
      addOpaque(sa.opaque, 'eval')
      return
    }
    sa.nested = await analyzeCommand(text, { ...ctx, shell, depth: ctx.depth + 1 })
  }

  /** Analyses `argvs` as one nested command with one segment each (every find -exec clause). */
  async function nestedArgvs(sa: SegmentAnalysis, argvs: string[][], ctx: Run) {
    if (argvs.length === 0) return
    if (ctx.depth >= MAX_DEPTH) {
      addOpaque(sa.opaque, 'eval')
      return
    }
    const segs: Segment[] = argvs.map((argv, index) => ({
      index,
      text: argv.join(' '),
      argv,
      operatorBefore: index === 0 ? null : ';',
      opaque: [],
      redirects: [],
    }))
    const text = segs.map((x) => x.text).join(' ; ')
    sa.nested = await analyzeSegments(text, segs, { ...ctx, depth: ctx.depth + 1 })
  }

  async function analyzeArgv(
    sa: SegmentAnalysis,
    argv: string[],
    ctx: Run,
    st: SegState,
    pos: number[] | null,
  ): Promise<void> {
    const stripped = stripWrappers(argv)
    sa.wrappers.push(...stripped.wrappers)
    st.assignments.push(...stripped.assignments)
    const rest = stripped.argv
    const restPos = subPositions(argv, pos, rest)
    const head = rest[0]
    if (head === undefined) return
    const name = programName(head)
    sa.program = name
    const spec = lookupTool(head, tools) ?? null
    if (spec?.category === 'interpreter') markHiddenCode(sa, name, rest, spec, ctx)

    const form = specialForm(rest, tools)
    if (!form) {
      if (spec) await parseTool(sa, rest, spec, ctx, st, restPos)
      return
    }
    for (const k of form.opaque) addOpaque(sa.opaque, k)
    if (form.script) {
      sa.wrappers.push(name)
      sa.program = programName(form.script.argv[0] as string)
      const scriptPos = subPositions(rest, restPos, form.script.argv)
      await parseTool(sa, form.script.argv, form.script.spec, ctx, st, scriptPos)
      return
    }
    if (form.outer && spec) {
      await parseTool(sa, form.outer, spec, ctx, st, subPositions(rest, restPos, form.outer))
    }
    for (const raw of form.targets ?? []) addTargetTo(sa, raw, 'positional', null)
    if (form.inline) {
      sa.wrappers.push(form.inline.wrapper)
      const inlinePos = subPositions(rest, restPos, form.inline.argv)
      await analyzeArgv(sa, form.inline.argv, ctx, st, inlinePos)
    }
    if (form.nestedText) await nestedText(sa, form.nestedText.text, ctx, form.nestedText.shell)
    if (form.nestedArgvs) await nestedArgvs(sa, form.nestedArgvs, ctx)
  }

  async function parseTool(
    sa: SegmentAnalysis,
    argv: string[],
    top: KnownToolSpec,
    ctx: Run,
    st: SegState,
    pos: number[] | null,
  ): Promise<void> {
    let spec = top
    let idx: FlagIndex = buildIndex(spec)
    sa.tool = top
    let subcommandPending = top.subcommands !== undefined
    let endOfOptions = false
    let positionals = 0
    const matched: NonNullable<KnownToolSpec['tierOverrides']> = []
    const files: { path: string; kind: 'targets' | 'excludes' | 'url-or-file' }[] = []
    const bruteforceCandidates: string[] = []

    const addTarget = (
      tok: string,
      provenance: ExtractedTarget['provenance'],
      source: string | null,
      role: ExtractedTarget['role'] = 'target',
    ) => addTargetTo(sa, tok, provenance, source, role)
    /** Keeps the word at argv index `k` out of the literal sweep. */
    const skip = (k: number | undefined) => {
      const p = k === undefined ? undefined : pos?.[k]
      if (p !== undefined) st.skip.add(p)
    }

    /** Non-network flags count only at the top level: before a subcommand or first positional. */
    const atTopLevel = () =>
      spec === top && !(top.subcommands && !subcommandPending) && positionals === 0

    const onFlag = (name: string, value: string | undefined, valueAt: number | undefined) => {
      const r = idx.roles.get(name)
      if (!r) return
      if (r.nonNetwork && atTopLevel()) sa.nonNetwork = true
      if (r.hardDeny && sa.hardDeny === null) sa.hardDeny = r.hardDeny
      if (r.credential) sa.credentials = true
      for (const o of r.overrides) {
        if (o.value === undefined || (value !== undefined && o.value.test(value))) matched.push(o)
      }
      if (r.rate) {
        const v = r.rateValue ?? value
        if (v !== undefined && !addRate(sa.rate, r.rate, name, v))
          addOpaque(sa.opaque, 'unparseable-rate')
      }
      if (value === undefined) return
      if (r.credentialHeader && AUTH_HEADER.test(value)) sa.credentials = true
      if (r.bruteforceFile) bruteforceCandidates.push(value)
      if (r.host || r.url) for (const part of listParts(value)) addTarget(part, 'flag', name)
      if (r.infra) {
        skip(valueAt)
        for (const part of listParts(value)) addTarget(part, 'flag', name, 'infra')
      }
      if (r.infraConfig.length > 0) {
        const eq = value.indexOf('=')
        if (eq > 0 && r.infraConfig.some((key) => key.test(value.slice(0, eq)))) {
          skip(valueAt)
          addTarget(value.slice(eq + 1), 'flag', name, 'infra')
        }
      }
      if (r.nonTarget) skip(valueAt)
      if (r.embedded) {
        skip(valueAt)
        for (const hit of embeddedTargets(r.embedded, value))
          addTarget(hit.raw, 'flag', name, hit.role)
      }
      // A list file's name is not a target (its lines are); keep it out of the literal sweep.
      if (r.file || r.excludeFile || r.urlOrFile) skip(valueAt)
      if (r.file) files.push({ path: value, kind: 'targets' })
      if (r.excludeFile) files.push({ path: value, kind: 'excludes' })
      if (r.urlOrFile) files.push({ path: value, kind: 'url-or-file' })
      if (r.exclude) {
        skip(valueAt)
        for (const part of listParts(value)) {
          const range = parseIpSpec(part)
          if (range) sa.excludes.push(range)
        }
      }
    }

    /** Returns false when the tool turns out to be an unknown subcommand (stop parsing). */
    const onPositional = (tok: string): boolean => {
      if (subcommandPending) {
        subcommandPending = false
        const sub = top.subcommands?.[tok]
        if (sub) {
          spec = mergeSpec(top, sub)
          idx = buildIndex(spec)
          return true
        }
        // P18: a tier-null tool's unknown subcommand is analysed like an unknown program.
        if (top.tier === null && !(top.localSubcommands ?? []).includes(tok)) return false
        return true
      }
      if (spec.optionsEndAtFirstPositional) endOfOptions = true
      if (spec.positionalTargets === false || tok === '-') return true
      if (spec.positionalSkip?.test(tok)) return true
      positionals++
      if (spec.positionalLimit !== undefined && positionals > spec.positionalLimit) return true
      if (spec.remotePositionals) {
        const remote = remoteToken(tok)
        if (remote !== undefined) addTarget(remote, 'positional', null)
        return true
      }
      addTarget(tok, 'positional', null)
      return true
    }

    for (let i = 1; i < argv.length; i++) {
      const tok = argv[i] as string
      if (!endOfOptions && tok === '--') {
        if (spec.afterDoubleDash) {
          await nestedArgvs(sa, [[spec.afterDoubleDash, ...argv.slice(i + 1)]], ctx)
          break
        }
        endOfOptions = true
        continue
      }
      const looksLikeOption =
        !endOfOptions &&
        tok.length > 1 &&
        (tok.startsWith('-') || tok.startsWith('/') || tok.startsWith('+'))
      const matches = looksLikeOption ? matchFlag(idx, tok) : []
      if (matches.length === 0) {
        if (looksLikeOption && tok.startsWith('-')) continue // an undocumented switch
        if (!onPositional(tok)) {
          if (top.category === 'vcs' || top.category === 'package-manager') {
            // P15: an unknown vcs/package subcommand may reach the implicit default
            // remote or registry, so it stays a network action of the parent tool.
            sa.category = top.category
            sa.tier = 'recon'
          } else {
            sa.tool = null
            sa.category = null
            sa.tier = null
          }
          return
        }
        continue
      }
      for (const m of matches) {
        const r = idx.roles.get(m.name)
        let value = m.attached
        let valueAt = value === undefined ? undefined : i
        const next = argv[i + 1]
        if (value === undefined && r?.takesValue && next !== undefined) {
          if (!r.optionalValue || !next.startsWith('-')) {
            i++
            value = next
            valueAt = i
          }
        }
        onFlag(m.name, value, valueAt)
      }
    }

    for (const f of files) {
      const path = f.path === '-' ? stdinFile(sa) : f.path
      const content = path === undefined ? undefined : await readListFile(path, ctx)
      if (f.kind === 'excludes') {
        if (content === undefined) continue
        for (const entry of listEntries(content)) {
          const range = parseIpSpec(entry)
          if (range) sa.excludes.push(range)
        }
        continue
      }
      if (f.kind === 'url-or-file' && content === undefined) {
        for (const part of listParts(f.path)) addTarget(part, 'flag', null)
        continue
      }
      if (content === undefined || f.path.includes('$')) {
        addOpaque(sa.opaque, 'unreadable-target-file')
        continue
      }
      for (const entry of listEntries(content)) addTarget(entry, 'file', f.path)
    }
    for (const value of bruteforceCandidates) {
      if (LIST_FILE_SHAPE.test(value) || (await readListFile(value, ctx)) !== undefined) {
        matched.push({ flag: 'list file', tier: 'bruteforce' })
      }
    }

    // Defence in depth: a segment with a flag, positional or file target is never non-network.
    if (sa.targets.some((t) => t.provenance !== 'literal')) sa.nonNetwork = false

    sa.category = spec.category
    let tier = spec.tier
    if (matched.length > 0) {
      tier = matched.reduce<Tier | 'dos'>(
        (best, o) => (TIER_RANK[o.tier] > TIER_RANK[best] ? o.tier : best),
        matched[0]?.tier ?? 'recon',
      )
      sa.intrusive = matched.some((o) => o.intrusive === true)
    }
    sa.tier = sa.nonNetwork ? null : tier
  }

  /** The file behind `< file` when a tool reads its target list from stdin (`-iL -`). */
  function stdinFile(sa: SegmentAnalysis): string | undefined {
    return sa.redirects.find((r) => r.op === '<')?.target
  }

  return {
    analyze(command, ctx) {
      return analyzeCommand(command, { ...ctx, depth: 0, written: new Set() })
    },
  }
}
