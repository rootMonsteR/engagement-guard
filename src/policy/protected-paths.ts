import { existsSync, realpathSync } from 'node:fs'
import { homedir } from 'node:os'
import path from 'node:path'
import { PROTECTED_HOME_ENTRIES, protectedCasePaths } from '../engagement/store.js'
import type { CommandAnalysis, SegmentAnalysis } from '../extract/extractor.js'
import { type GuardPaths, HOME_ENV } from '../paths.js'
import { base } from './command-views.js'

/**
 * Ruling P24: the model never writes the case file, the frozen scope snapshots, the audit log or the
 * home's acknowledgement and keys (`protectedCasePaths`). The operator edits the case outside the
 * model and attests the change (`GuardPaths.commandHint`).
 *
 * Paths are compared case-folded with `/` separators on every platform (macOS and Windows file
 * systems are case-insensitive, and over-blocking a differently-cased twin on Linux is harmless).
 * Each path is compared in two forms: lexical (Windows `\\?\X:` / `\\.\X:` / `\??\X:` prefixes
 * removed, NTFS stream suffixes and trailing dots/spaces dropped) and canonical (the deepest existing
 * ancestor through `realpathSync.native`, which expands 8.3 short names and follows junctions and
 * symlinks). A Windows path without a drive letter (UNC, an admin share `\\host\c$`, a volume GUID,
 * `GLOBALROOT`) is never touched on disk — that could contact the network — and is protected by
 * name: any component naming the workspace directory (`GuardPaths.dirName`, `.guard`),
 * `engagement.yaml`, or the home's `first-run.json`/`keys`.
 *
 * A write must not land on or inside a protected path. A copy, move, link or extraction must not
 * target the directory of a protected file (`cp x .guard/`), nor carry a protected name or a
 * directory's contents into an ancestor; an archive extracted into an ancestor is a possible hit (the
 * guard asks: the archive's contents are unknown). A removal, rename or permission change must not
 * touch a protected path, anything inside it, or any directory that contains it (`.guard`, the
 * workspace itself). A protected file is never a link source (`ln`, `cp -l`, `fsutil hardlink`).
 *
 * Known limits (documented, spec §6.5 honest gaps): writes made by interpreters and programs the
 * guard does not model (`python -c "open(…,'w')"`, editors, `git apply`, `git checkout <rev> -- .`),
 * archives extracted into the working directory without `-C`/`-d`, downloads into the working
 * directory after `cd .guard` with a server-chosen name (`curl -O`), and symlinks or junctions
 * created and then written through within one command (a race against the canonical check).
 */
export interface ProtectedHit {
  /** The protected entry that matched (`/w/.guard/audit/**`). */
  rule: string
  /** The path as the command or tool named it. */
  path: string
  /** The hit is only possible (an archive extracted into an ancestor): the guard asks. */
  possible?: boolean
}

/** Where the protected paths live: every workspace that may hold the case, and the home. */
export interface ProtectedScope {
  /** The request's working directory: relative paths resolve against it. */
  cwd: string
  /** The workspace paths (relative) and the home (`<home>/first-run.json`, `<home>/keys`). */
  paths: GuardPaths
  /** Further workspaces whose case paths are protected too (the case store's). */
  workspaces?: readonly string[]
}

interface Form {
  root: string
  segments: string[]
}

interface Root {
  /** The lexical and (when it differs) canonical form of the protected path. */
  forms: Form[]
  dir: boolean
  rule: string
}

type Effect =
  | { kind: 'write' | 'destroy'; raw: string }
  /**
   * A copy/move/link/extract destination; `sources` are what lands there, `contents` when a
   * directory's whole contents (dotfiles included) may land there (`cp -r x/. .`, `rsync -a x/ .`),
   * `archive` for an extraction whose contents are unknown.
   */
  | { kind: 'into'; raw: string; sources: string[]; contents: boolean; archive?: boolean }

const OUTPUT_REDIRECTS: ReadonlySet<string> = new Set(['>', '>>', '>|', '&>', '&>>', '<>'])
const DESTROY_ALL = new Set([
  'rm',
  'rmdir',
  'unlink',
  'shred',
  'srm',
  'wipe',
  'chmod',
  'chown',
  'chgrp',
  'chattr',
  'setfacl',
])
/** Every operand is written (or becomes a link to / of a written name). */
const WRITE_ALL = new Set(['tee', 'touch', 'truncate', 'fsutil', 'mklink'])
const IN_PLACE = new Set(['sed', 'perl', 'ruby', 'gsed'])
/** Editors that save their file operand, scripted or not (`ex -s -c wq x`, `vim -es +wq x`, `nano x`). */
const EDITORS = new Set([
  'vi',
  'vim',
  'nvim',
  'gvim',
  'ex',
  'ed',
  'nano',
  'pico',
  'emacs',
  'micro',
  'joe',
  'code',
  'subl',
  'gedit',
  'notepad',
  'notepad++',
])
/** Programs `find -exec` can run without changing what it found. */
const READ_ONLY = new Set([
  'cat',
  'grep',
  'egrep',
  'fgrep',
  'rg',
  'ls',
  'file',
  'stat',
  'head',
  'tail',
  'wc',
  'echo',
  'printf',
  'md5sum',
  'sha1sum',
  'sha256sum',
  'du',
  'realpath',
  'readlink',
  'basename',
  'dirname',
  'test',
  '[',
  'true',
  'false',
  'strings',
  'xxd',
  'hexdump',
  'od',
  'less',
  'more',
  'diff',
  'cmp',
  'sort',
  'uniq',
  'cut',
  'jq',
  'yq',
  'tr',
  'nl',
  'identify',
  'exiftool',
])
const CD = new Set(['cd', 'pushd', 'chdir', 'set-location', 'sl', 'push-location'])
/** PowerShell cmdlets and aliases that write, move, link or remove items. */
const PS_WRITERS = new Set([
  'remove-item',
  'ri',
  'del',
  'erase',
  'rd',
  'set-content',
  'sc',
  'add-content',
  'ac',
  'out-file',
  'clear-content',
  'clc',
  'new-item',
  'ni',
  'copy-item',
  'cpi',
  'copy',
  'move-item',
  'mi',
  'move',
  'rename-item',
  'ren',
  'rni',
  'set-acl',
])
const PS_WRITER_TEXT =
  /\b(?:remove-item|ri|del|erase|rd|rm|rmdir|set-content|sc|add-content|ac|out-file|clear-content|clc|new-item|ni|copy-item|cpi|copy|cp|move-item|mi|move|mv|rename-item|ren|rni|set-acl|expand-archive|fsutil|mklink)\b|>/i
/** PowerShell web cmdlets (and their aliases) whose `-OutFile` writes a file. */
const PS_DOWNLOADERS = new Set([
  'invoke-webrequest',
  'iwr',
  'invoke-restmethod',
  'irm',
  'curl',
  'wget',
])
/** `-OutFile` and its unambiguous abbreviations, `-OutFile:x` included. */
const PS_OUTFILE = /^-outf(?:i(?:le?)?)?(?::(.*))?$/i
/** `Start-BitsTransfer -Destination` (`-Dest…`). */
const PS_DESTINATION = /^-dest(?:i(?:n(?:a(?:t(?:i(?:on?)?)?)?)?)?)?(?::(.*))?$/i
/** `Expand-Archive -DestinationPath` (`-D…` is unambiguous). */
const PS_DESTINATION_PATH = /^-d(?:[a-z]*)(?::(.*))?$/i

/** Flags whose value is a file the tool writes, for any program (`-o out`, `--output=out`). */
const GENERIC_OUTPUT = ['-o', '--output', '--output-file', '--outfile', '-out', '--out']
/** Per program: flags whose value is a file the tool writes (single letters also inside clusters). */
const OUTPUT_FLAGS: Readonly<Record<string, readonly string[]>> = {
  curl: [
    '-o',
    '-D',
    '--dump-header',
    '-c',
    '--cookie-jar',
    '--trace',
    '--trace-ascii',
    '--stderr',
    '--etag-save',
    '--hsts',
    '--alt-svc',
  ],
  wget: ['-O', '-o', '--output-document', '-a', '--append-output', '--save-cookies', '--warc-file'],
  nmap: ['-oN', '-oX', '-oG', '-oA', '-oS', '-oM', '-oH'],
  masscan: ['-oX', '-oG', '-oJ', '-oL', '-oB', '-oD', '-oU', '--output-filename'],
  nuclei: ['-je', '-jsonl-export', '-me', '-markdown-export', '-se', '-sarif-export'],
  ffuf: ['-debug-log'],
  tcpdump: ['-w'],
  tshark: ['-w'],
  dumpcap: ['-w'],
  openssl: ['-keyout'],
  'ssh-keygen': ['-f'],
}
/** Per program: flags whose value is a directory the tool writes into. */
const OUTPUT_DIR_FLAGS: Readonly<Record<string, readonly string[]>> = {
  curl: ['--output-dir'],
  wget: ['-P', '--directory-prefix'],
  httpx: ['-srd', '-store-response-dir'],
  subfinder: ['-oD', '-output-dir'],
  ffuf: ['-od'],
  sqlmap: ['--output-dir'],
}
/** Per program: flags whose value is a directory an archive is extracted into. */
const ARCHIVE_DIR_FLAGS: Readonly<Record<string, readonly string[]>> = {
  unzip: ['-d'],
  '7z': ['-o'],
  '7za': ['-o'],
}

/**
 * Option grammar of the copy-like programs: short letters and long options that take a value, and
 * whether `-t DIR` names the target directory (rsync's `-t` is `--times`, scp has none).
 */
interface CopySpec {
  short: string
  long: readonly string[]
  target: boolean
}
const GNU_COPY: CopySpec = {
  short: 'St',
  long: ['--suffix', '--target-directory', '--reflink', '--sparse'],
  target: true,
}
const COPY_SPECS: Readonly<Record<string, CopySpec>> = {
  cp: GNU_COPY,
  mv: GNU_COPY,
  ln: GNU_COPY,
  link: { short: '', long: [], target: false },
  install: {
    short: 'Stmog',
    long: ['--suffix', '--target-directory', '--mode', '--owner', '--group', '--strip-program'],
    target: true,
  },
  rsync: {
    short: 'efBTM',
    long: [
      '--exclude',
      '--include',
      '--filter',
      '--exclude-from',
      '--include-from',
      '--files-from',
      '--rsh',
      '--rsync-path',
      '--temp-dir',
      '--partial-dir',
      '--backup-dir',
      '--suffix',
      '--chmod',
      '--chown',
      '--compare-dest',
      '--copy-dest',
      '--link-dest',
      '--log-file',
      '--log-file-format',
      '--out-format',
      '--password-file',
      '--port',
      '--timeout',
      '--contimeout',
      '--bwlimit',
      '--max-size',
      '--min-size',
      '--max-delete',
      '--modify-window',
      '--usermap',
      '--groupmap',
      '--iconv',
      '--block-size',
      '--compress-level',
      '--skip-compress',
      '--sockopts',
      '--address',
      '--protocol',
      '--checksum-choice',
      '--info',
      '--debug',
      '--stop-after',
      '--stop-at',
      '--remote-option',
      '--outbuf',
      '--write-batch',
      '--read-batch',
      '--only-write-batch',
    ],
    target: false,
  },
  scp: { short: 'cFiJloPSD', long: [], target: false },
}

const GLOB = /[*?[]/

/** Separators to `/`, case-folded, no trailing slash (except a root). */
function fold(p: string): string {
  const s = p.replace(/\\/g, '/').replace(/\/+/g, '/').toLowerCase()
  const unc = /^[\\/]{2}[^\\/]/.test(p) ? '/' : ''
  const out = unc + s
  return out.length > 1 && out.endsWith('/') && !/^[a-z]:\/$/.test(out) ? out.slice(0, -1) : out
}

const isWindowsPath = (p: string) => /^[A-Za-z]:[\\/]/.test(p) || /^[\\/]{2}[^\\/]/.test(p)
const isAbsolute = (p: string) => path.posix.isAbsolute(p) || path.win32.isAbsolute(p)
/** A folded absolute Windows path that starts with a drive letter. */
const onDrive = (folded: string) => /^[a-z]:\//.test(folded)

/**
 * `\\?\C:\x`, `\\.\C:\x`, `\??\C:\x` → `C:\x`; `\\?\UNC\srv\share\x` → `\\srv\share\x`. Other device
 * paths (`\\?\Volume{…}\…`, `\\?\GLOBALROOT\…`) are kept: they are protected by name.
 */
function stripDevicePrefix(p: string): string {
  const unc = /^[\\/]{2}[?.][\\/]unc[\\/](.*)$/i.exec(p)
  if (unc) return `\\\\${unc[1] ?? ''}`
  const dev = /^(?:[\\/]{2}[?.]|[\\/]\?\?)[\\/]([A-Za-z]:(?:[\\/].*)?)$/.exec(p)
  return dev ? (dev[1] ?? '') : p
}

/**
 * Win32 names the file system itself rewrites: `name:stream` (an NTFS alternate data stream of
 * `name`) and trailing dots and spaces (`engagement.yaml.` opens `engagement.yaml`).
 */
function win32Components(abs: string): string {
  const m = /^([A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+[\\/]?)(.*)$/.exec(abs)
  if (!m) return abs
  const rest = (m[2] ?? '')
    .split(/[\\/]/)
    .map((c) => {
      const noStream = c.includes(':') ? c.slice(0, c.indexOf(':')) : c
      const trimmed = noStream.replace(/[. ]+$/, '')
      return trimmed === '' ? noStream : trimmed
    })
    .join('\\')
  return `${m[1]}${rest}`
}

interface Scan {
  roots: Root[]
  win: boolean
  /** Folded basenames of the home: `<base>/first-run.json` and `<base>/keys` are protected by name. */
  homeBases: Set<string>
  /** The folded workspace directory name (`.guard`). */
  dir: string
  /** The folded leaf name of the case file (`engagement.yaml`). */
  caseFile: string
  /**
   * Markers of a protected path in text the guard cannot resolve (`$HOME/...`, PowerShell
   * bodies): the workspace paths, `<home base>/first-run.json`, `<home base>/keys`, `guard_home`.
   */
  markers: string[]
  /** Path components that may name a protected path when the directory is unknown. */
  suspect: Set<string>
  /** The workspace directory as a whole path component of (folded) command text. */
  dirComponent: RegExp
}

const leaf = (p: string) => fold(p).split('/').at(-1) ?? ''
const escapeRegExp = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/** The absolute path `raw` names from `dir`, in the platform's spelling (original case). */
function lexical(win: boolean, dir: string, raw: string): string {
  let p = raw
  if (p === '~' || p.startsWith('~/') || p.startsWith('~\\')) p = homedir() + p.slice(1)
  if (!win) return path.posix.resolve(dir, p)
  p = stripDevicePrefix(p)
  // MSYS / Git Bash spelling of a drive (`/c/Users/...`).
  const msys = /^\/([A-Za-z])(\/|$)(.*)$/.exec(p)
  if (msys) p = `${msys[1]}:/${msys[3] ?? ''}`
  return win32Components(path.win32.resolve(stripDevicePrefix(dir), p))
}

/** The path with its deepest existing ancestor resolved by the OS; `undefined` when not possible. */
function canonical(win: boolean, abs: string): string | undefined {
  // Only drive paths are touched on Windows: UNC and device paths may contact the network.
  if (win && !onDrive(fold(abs))) return undefined
  const P = win ? path.win32 : path.posix
  try {
    let cur = abs
    const rest: string[] = []
    while (!existsSync(cur)) {
      const parent = P.dirname(cur)
      if (parent === cur) return undefined
      rest.unshift(P.basename(cur))
      cur = parent
    }
    return P.join(realpathSync.native(cur), ...rest)
  } catch {
    return undefined
  }
}

/** The folded lexical and canonical forms of `abs` (one entry when they agree). */
function formsOf(win: boolean, abs: string): string[] {
  const lex = fold(abs)
  const can = GLOB.test(abs) ? undefined : canonical(win, abs)
  const canFolded = can === undefined ? undefined : fold(can)
  return canFolded === undefined || canFolded === lex ? [lex] : [lex, canFolded]
}

function scanFor(scope: ProtectedScope): Scan {
  const win = isWindowsPath(scope.cwd)
  const seen = new Set<string>()
  const roots: Root[] = []
  const workspaces = [scope.cwd, ...(scope.workspaces ?? [])]
  for (const ws of workspaces) {
    for (const rule of protectedCasePaths(ws, scope.paths)) {
      const dir = rule.endsWith('/**')
      const raw = dir ? rule.slice(0, -3) : rule
      const abs = lexical(win || isWindowsPath(raw), '/', raw)
      const forms = formsOf(win || isWindowsPath(raw), abs).map((root) => ({
        root,
        segments: root.split('/'),
      }))
      const key = forms.map((f) => f.root).join('|')
      if (seen.has(key)) continue
      seen.add(key)
      roots.push({ forms, dir, rule })
    }
  }
  const { home, dirName, engagementPath, auditDir, casesDir } = scope.paths
  const homeBases = new Set<string>()
  for (const f of formsOf(win || isWindowsPath(home), home)) {
    const b = fold(f).split('/').at(-1)
    if (b) homeBases.add(b)
  }
  const dir = fold(dirName)
  const markers = [
    fold(engagementPath),
    fold(auditDir),
    fold(casesDir),
    ...[...homeBases].flatMap((b) => PROTECTED_HOME_ENTRIES.map((e) => `${b}/${e}`)),
    HOME_ENV.toLowerCase(),
  ]
  const suspect = new Set([
    dir,
    leaf(engagementPath),
    leaf(auditDir),
    leaf(casesDir),
    ...PROTECTED_HOME_ENTRIES,
  ])
  const dirComponent = new RegExp(`(?:^|[\\s'"=:/])${escapeRegExp(dir)}(?:[\\s'"/]|$)`)
  return {
    roots,
    win,
    homeBases,
    dir,
    caseFile: leaf(engagementPath),
    markers,
    suspect,
    dirComponent,
  }
}

const within = (p: string, root: string) =>
  p === root || p.startsWith(root.endsWith('/') ? root : `${root}/`)

/** A shell glob segment as a regular expression; `*`/`?` never match a leading dot. */
function segmentRegex(seg: string): RegExp {
  let re = ''
  for (let i = 0; i < seg.length; i++) {
    const ch = seg[i] as string
    if (ch === '*') re += '[^/]*'
    else if (ch === '?') re += '[^/]'
    else if (ch === '[') {
      const close = seg.indexOf(']', i + 1)
      if (close < 0) re += '\\['
      else {
        re += `[${seg
          .slice(i + 1, close)
          .replace(/^!/, '^')
          .replace(/\\/g, '\\\\')}]`
        i = close
      }
    } else re += ch.replace(/[.+^${}()|\\]/g, '\\$&')
  }
  return new RegExp(`^${re}$`)
}

function segmentMatches(pattern: string, name: string): boolean {
  if (!GLOB.test(pattern)) return pattern === name
  if (name.startsWith('.') && !pattern.startsWith('.')) return false
  return segmentRegex(pattern).test(name)
}

/** Whether the folded path `p` (possibly a glob) touches the root form under a write or removal. */
function touches(p: string, r: Form, dir: boolean, destroy: boolean): boolean {
  if (!GLOB.test(p)) {
    if (dir ? within(p, r.root) : p === r.root) return true
    return destroy && within(r.root, p)
  }
  const segs = p.split('/')
  const n = Math.min(segs.length, r.segments.length)
  for (let i = 0; i < n; i++) {
    if (!segmentMatches(segs[i] as string, r.segments[i] as string)) return false
  }
  if (segs.length > r.segments.length) return dir
  if (segs.length === r.segments.length) return true
  return destroy
}

type Match = 'certain' | 'possible' | undefined

/**
 * Whether a copy/move/link/extract into the folded directory `d` can create or replace the root:
 * `d` is the directory of the root (or inside it), or an ancestor that receives a source named like
 * the next component (`cp -r x/.guard .`), or a directory's whole contents; an archive extracted
 * into an ancestor may contain anything (possible).
 */
function into(d: string, r: Form, dir: boolean, e: Extract<Effect, { kind: 'into' }>): Match {
  if (touches(d, r, dir, false)) return 'certain'
  const parentSegs = dir ? r.segments : r.segments.slice(0, -1)
  const parent = parentSegs.join('/')
  if (d === parent) return 'certain'
  if (!within(parent, d) || GLOB.test(d)) return undefined
  if (e.archive === true) return 'possible'
  const next = r.segments[d.split('/').length] ?? ''
  if (e.contents) return 'certain'
  return e.sources.some((s) => segmentMatches(fold(s).split('/').at(-1) ?? '', next))
    ? 'certain'
    : undefined
}

/** A path the guard cannot resolve names a protected path by one of its components. */
function suspectByName(s: Scan, folded: string, e: Effect): boolean {
  const comps = folded.split('/')
  const homeEntry = (c: string | undefined) => PROTECTED_HOME_ENTRIES.some((entry) => entry === c)
  return (
    s.markers.some((m) => folded.includes(m)) ||
    comps.includes(s.dir) ||
    comps.includes(s.caseFile) ||
    comps.some((c, i) => s.homeBases.has(c) && homeEntry(comps[i + 1])) ||
    (e.kind !== 'write' && comps.at(-1) === s.dir)
  )
}

/** Checks one effect; `dir` is `null` when an earlier `cd` made the directory unknown. */
function check(s: Scan, dir: string | null, e: Effect, literal: boolean): ProtectedHit | undefined {
  const raw = e.raw
  if (raw === '' || raw === '-') return undefined
  const destroy = e.kind === 'destroy'
  const archive = e.kind === 'into' && e.archive === true
  // `x/./y` is `x/y`; `x/.` is `x`.
  const text = fold(raw).replace(/\/\.(?=\/|$)/g, '')
  const expands = !literal && (raw.includes('$') || raw.includes('`'))
  if (expands || (dir === null && !isAbsolute(raw))) {
    // The text cannot be resolved: fail closed on anything that looks like a protected path.
    const suspect =
      s.markers.some((m) => text.includes(m)) ||
      ((destroy || e.kind === 'into') && (text === s.dir || text.endsWith(`/${s.dir}`))) ||
      (!expands &&
        text
          .split('/')
          .some(
            (c) =>
              s.suspect.has(c) || ((destroy || e.kind === 'into') && (c === '.' || c === '..')),
          ))
    if (suspect) return { rule: 'protected case paths (unresolved path)', path: raw }
    // An archive extracted somewhere unknown may land on the case directory.
    return archive
      ? {
          rule: 'protected case paths (unresolved extraction directory)',
          path: raw,
          possible: true,
        }
      : undefined
  }
  const abs = lexical(s.win, dir ?? '/', raw)
  const forms = formsOf(s.win, abs)
  let possible: ProtectedHit | undefined
  for (const r of s.roots) {
    for (const f of forms) {
      for (const rf of r.forms) {
        const m: Match =
          e.kind === 'into'
            ? into(f, rf, r.dir, e)
            : touches(f, rf, r.dir, destroy)
              ? 'certain'
              : undefined
        if (m === 'certain') return { rule: r.rule, path: raw }
        if (m === 'possible') possible ??= { rule: r.rule, path: raw, possible: true }
      }
    }
  }
  if (possible !== undefined) return possible
  // Fix round 2 (C1): UNC, admin shares, volume GUIDs, GLOBALROOT — protected by name.
  if (s.win && !onDrive(fold(abs)) && suspectByName(s, fold(abs), e)) {
    return { rule: 'protected case paths (Windows path without a drive letter)', path: raw }
  }
  return undefined
}

/** Operands of `args`: words that are not options (everything after `--`). */
function operands(args: string[]): string[] {
  const out: string[] = []
  let end = false
  for (const a of args) {
    if (!end && a === '--') {
      end = true
      continue
    }
    if (!end && a.startsWith('-') && a.length > 1) continue
    out.push(a)
  }
  return out
}

/**
 * Values of `flags` in `args`: `-f x`, `--flag=x`, attached `-fx` / `-oNx`, and — for single
 * letters — a short-option cluster that sets the letter (`-sSLo x`, `-qOx`).
 */
function flagValues(args: string[], flags: readonly string[], clusters = false): string[] {
  const out: string[] = []
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string
    for (const f of flags) {
      if (a === f) {
        const v = args[i + 1]
        if (v !== undefined) out.push(v)
      } else if (a.startsWith(`${f}=`)) out.push(a.slice(f.length + 1))
      else if (!f.startsWith('--') && a.startsWith(f) && a.length > f.length) {
        out.push(a.slice(f.length))
      } else if (clusters && /^-[A-Za-z]$/.test(f) && /^-[A-Za-z]/.test(a) && !a.startsWith('--')) {
        const at = a.indexOf(f[1] as string, 1)
        if (at > 0 && /^-[A-Za-z]+$/.test(a.slice(0, at + 1))) {
          const rest = a.slice(at + 1)
          const v = rest !== '' ? rest : args[i + 1]
          if (v !== undefined) out.push(v)
        }
      }
    }
  }
  return out
}

/** Values of PowerShell parameters matching `name` (`-OutFile x`, `-OutFile:x`). */
function psParamValues(args: string[], name: RegExp): string[] {
  const out: string[] = []
  for (let i = 0; i < args.length; i++) {
    const m = name.exec(args[i] as string)
    if (m === null) continue
    const v = m[1] !== undefined && m[1] !== '' ? m[1] : args[i + 1]
    if (v !== undefined) out.push(v)
  }
  return out
}

/** Whether an option cluster or long option in `args` sets the letter or names the long form. */
function hasSwitch(args: string[], letter: string, long: readonly string[]): boolean {
  return args.some(
    (a) =>
      long.includes(a) || (/^-[A-Za-z]+$/.test(a) && !a.startsWith('--') && a.includes(letter)),
  )
}

/** `[program, args]` of a segment after its wrappers (`sudo rm …` → `rm`, `[…]`). */
function commandOf(seg: SegmentAnalysis): { program: string; args: string[] } | undefined {
  if (seg.program === null) return undefined
  const program = base(seg.program)
  const k = seg.argv.findIndex((t) => base(t) === program)
  return { program, args: seg.argv.slice((k >= 0 ? k : 0) + 1) }
}

interface CopyArgs {
  target: string | undefined
  files: string[]
  recursive: boolean
  /** `cp -l` / `--link`: the sources become hard links. */
  link: boolean
}

/** A copy-like command line read with its program's option grammar (values skipped wherever they are). */
function parseCopy(program: string, args: string[], spec: CopySpec): CopyArgs {
  const r: CopyArgs = { target: undefined, files: [], recursive: false, link: false }
  let end = false
  for (let i = 0; i < args.length; i++) {
    const a = args[i] as string
    if (end || a === '-' || !a.startsWith('-')) {
      r.files.push(a)
      continue
    }
    if (a === '--') {
      end = true
      continue
    }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=')
      const name = eq >= 0 ? a.slice(0, eq) : a
      let value = eq >= 0 ? a.slice(eq + 1) : undefined
      if (value === undefined && spec.long.includes(name)) value = args[++i]
      if (name === '--target-directory' && spec.target) r.target = value
      if (name === '--recursive' || name === '--archive') r.recursive = true
      if (name === '--link' && program === 'cp') r.link = true
      continue
    }
    for (let j = 1; j < a.length; j++) {
      const ch = a[j] as string
      if (spec.short.includes(ch)) {
        const value = j + 1 < a.length ? a.slice(j + 1) : args[++i]
        if (ch === 't' && spec.target) r.target = value
        break
      }
      if (ch === 'r' || ch === 'R' || ch === 'a') r.recursive = true
      if (ch === 'l' && program === 'cp') r.link = true
    }
  }
  return r
}

/** `host:path` (scp/rsync remote), not a Windows drive. */
const isRemote = (p: string) => /^[^/\\]+:/.test(p) && !/^[A-Za-z]:[\\/]?/.test(p)

/** The paths one segment writes, moves, links or removes. */
function effectsOf(seg: SegmentAnalysis): Effect[] {
  const out: Effect[] = []
  for (const r of seg.redirects) {
    if (OUTPUT_REDIRECTS.has(r.op)) out.push({ kind: 'write', raw: r.target })
  }
  const cmd = commandOf(seg)
  if (cmd === undefined) return out
  const { program, args } = cmd
  const ops = operands(args)
  const all = (kind: 'write' | 'destroy') => {
    for (const raw of ops) out.push({ kind, raw })
  }
  for (const raw of flagValues(args, GENERIC_OUTPUT)) out.push({ kind: 'write', raw })
  for (const raw of flagValues(args, OUTPUT_FLAGS[program] ?? [], true)) {
    out.push({ kind: 'write', raw })
  }
  for (const raw of flagValues(args, OUTPUT_DIR_FLAGS[program] ?? [])) {
    out.push({ kind: 'into', raw, sources: [], contents: false })
  }
  for (const raw of flagValues(args, ARCHIVE_DIR_FLAGS[program] ?? [])) {
    out.push({ kind: 'into', raw, sources: [], contents: false, archive: true })
  }
  // A download that keeps the remote file name lands in the working directory, which may be the
  // case directory after a `cd` (`cd .guard && curl -O …`, `wget …` with no `-O`/`-P`).
  const shortFlag = (letters: string) =>
    args.some((a) => !a.startsWith('--') && new RegExp(`^-[A-Za-z]*[${letters}]`).test(a))
  const remoteName =
    (program === 'curl' &&
      (shortFlag('OJ') || args.some((a) => /^--remote-(?:name|name-all|header-name)$/.test(a)))) ||
    (program === 'wget' &&
      !shortFlag('OP') &&
      !args.some((a) => /^--(?:output-document|directory-prefix)(?:=|$)/.test(a)) &&
      !args.includes('--spider'))
  if (remoteName && flagValues(args, OUTPUT_DIR_FLAGS[program] ?? []).length === 0) {
    out.push({ kind: 'into', raw: '.', sources: [], contents: false })
  }
  if (PS_DOWNLOADERS.has(program)) {
    for (const raw of psParamValues(args, PS_OUTFILE)) out.push({ kind: 'write', raw })
  }
  if (program === 'start-bitstransfer') {
    for (const raw of psParamValues(args, PS_DESTINATION)) out.push({ kind: 'write', raw })
  }
  const copy = COPY_SPECS[program]
  if (DESTROY_ALL.has(program) || PS_WRITERS.has(program)) all('destroy')
  else if (WRITE_ALL.has(program) || EDITORS.has(program)) all('write')
  else if (copy !== undefined) {
    const c = parseCopy(program, args, copy)
    const sources = c.target !== undefined ? c.files : c.files.slice(0, -1)
    const linking = program === 'ln' || program === 'link'
    const dest = c.target ?? (c.files.length > 1 ? c.files.at(-1) : linking ? '.' : undefined)
    // `x/.` (and rsync's `x/`) deliver the directory's contents, dotfiles included; mv never does.
    const contents =
      program !== 'mv' &&
      c.recursive &&
      sources.some(
        (src) => src === '.' || /[\\/]\.$/.test(src) || (program === 'rsync' && /[\\/]$/.test(src)),
      )
    if (program === 'mv') for (const raw of sources) out.push({ kind: 'destroy', raw })
    // Fix round 2 (M12): a protected file never becomes a link source (hard or symbolic). Review of
    // 2026-10-19: nor does its directory or an ancestor, which would alias it for a later write
    // (`ln -s .guard gg; echo x > gg/engagement.yaml`), so link operands are judged like a removal.
    if (linking || c.link) for (const raw of c.files) out.push({ kind: 'destroy', raw })
    if (dest !== undefined && !isRemote(dest)) {
      out.push({ kind: 'into', raw: dest, sources, contents })
    }
  } else if (IN_PLACE.has(program)) {
    if (args.some((a) => /^-[A-Za-z]*i/.test(a) || a.startsWith('--in-place'))) all('write')
  } else if (program === 'dd') {
    for (const a of args) if (a.startsWith('of=')) out.push({ kind: 'write', raw: a.slice(3) })
  } else if (program === 'find') {
    // `-delete`, or `-exec`/`-ok` (and the `dir` forms) running anything but a reader, may remove
    // or rewrite whatever lies under the start directories (`.` when none is given).
    const execs = args.flatMap((a, i) =>
      /^-(?:exec|execdir|ok|okdir)$/.test(a) ? [base(args[i + 1] ?? '')] : [],
    )
    if (args.includes('-delete') || execs.some((p) => !READ_ONLY.has(p))) {
      const starts: string[] = []
      for (const a of args) {
        if (/^-[HLP]$|^-[OD]/.test(a)) continue
        if (a.startsWith('-') || a === '(' || a === '!') break
        starts.push(a)
      }
      for (const raw of starts.length > 0 ? starts : ['.']) out.push({ kind: 'destroy', raw })
    }
  } else if (program === 'expand-archive') {
    const named = psParamValues(args, PS_DESTINATION_PATH)
    const positional = ops[1]
    for (const raw of named.length > 0 ? named : positional !== undefined ? [positional] : []) {
      out.push({ kind: 'into', raw, sources: [], contents: false, archive: true })
    }
  } else if (program === 'tar' || program === 'bsdtar') {
    const first = args[0] ?? ''
    const oldStyle = /^[A-Za-z]+$/.test(first) ? first : ''
    const creating =
      hasSwitch(args, 'c', ['--create', '--append', '--update']) ||
      hasSwitch(args, 'r', []) ||
      hasSwitch(args, 'u', []) ||
      /[cru]/.test(oldStyle)
    if (creating) {
      for (const raw of flagValues(args, ['--file'])) out.push({ kind: 'write', raw })
      // `-f x`, `-czf x` (f ends a cluster: the next word), `-fx` / `-czfx` (attached).
      for (let i = 0; i < args.length; i++) {
        const m = /^-[A-Za-z]*f(.*)$/.exec(args[i] as string)
        if (m === null || (args[i] as string).startsWith('--')) continue
        const raw = m[1] !== '' ? m[1] : args[i + 1]
        if (raw !== undefined) out.push({ kind: 'write', raw })
      }
      if (oldStyle.includes('f')) {
        const raw = ops[1]
        if (raw !== undefined) out.push({ kind: 'write', raw })
      }
    } else {
      for (const raw of flagValues(args, ['-C', '--directory'])) {
        out.push({ kind: 'into', raw, sources: [], contents: false, archive: true })
      }
    }
  } else if (program === 'git') {
    const sub = ops[0]
    if (sub === 'clean' && args.some((a) => /^-[A-Za-z]*[dxX]/.test(a))) {
      out.push({ kind: 'destroy', raw: '.' })
    } else if (sub === 'rm' || sub === 'mv' || sub === 'checkout' || sub === 'restore') {
      // A pathspec replaces or removes everything under it (`git checkout -- .guard`).
      for (const raw of ops.slice(1)) out.push({ kind: 'destroy', raw })
    }
  }
  return out
}

/** The directory a `cd`-like segment moves to; `null` when unknown; `undefined` when not a cd. */
function cdTarget(seg: SegmentAnalysis, s: Scan, dir: string | null): string | null | undefined {
  const cmd = commandOf(seg)
  if (cmd === undefined || !CD.has(cmd.program)) return undefined
  const ops = operands(cmd.args.filter((a) => !/^-(?:path|literalpath)$/i.test(a)))
  const target = ops[0]
  if (target === undefined) return homedir()
  if (target === '-' || target.includes('$') || target.includes('`') || GLOB.test(target)) {
    return null
  }
  if (dir === null && !isAbsolute(target)) return null
  return lexical(s.win, dir ?? '/', target)
}

interface ScanResult {
  certain?: ProtectedHit
  possible?: ProtectedHit
  /** Some segment writes, moves, links or extracts something (for the PowerShell text check). */
  writes: boolean
}

const SELF_MUTATING: ReadonlySet<string> = new Set(['ack', 'init'])
const SELF_ENGAGEMENT: ReadonlySet<string> = new Set(['new', 'freeze', 'edit', 'load'])
/**
 * The CLI entry of this package by path: under an `engagement-guard` directory, `dist/cli/bin.js`,
 * `src/cli/bin.ts`, or the `.bin/engagement-guard` shim.
 */
const SELF_BIN =
  /(?:^|[\\/])(?:engagement-guard[\\/].*[\\/]cli[\\/]bin\.[jt]s|dist[\\/]cli[\\/]bin\.js|src[\\/]cli[\\/]bin\.ts|\.bin[\\/]engagement-guard(?:\.cmd|\.ps1)?)$/i
/**
 * The binary and a mutating subcommand inside one word: an inline script (`expect -c "spawn
 * engagement-guard ack …"`, `pty.spawn(['engagement-guard', 'ack'])`).
 */
const SELF_INLINE =
  /(?:^|[^A-Za-z0-9_.-])engagement-guard(?:\.cmd|\.exe|\.ps1)?["'\]]*[\s,]+["'[]*(?:ack|init|engagement["'\]]*[\s,]+["'[]*(?:new|freeze|edit|load))(?![A-Za-z0-9_-])/i

/** Whether `word` names this package's binary: the bare name (with a shim extension), a path to it, or its entry file. */
function namesSelf(word: string): boolean {
  const leafName = (word.replace(/\\/g, '/').split('/').at(-1) ?? '')
    .toLowerCase()
    .replace(/\.(?:cmd|exe|ps1|bat)$/, '')
  return leafName === 'engagement-guard' || SELF_BIN.test(word)
}

/** The mutating subcommand that starts at `words[i]`, if any. */
function mutatingAt(words: string[], i: number): string | undefined {
  const sub = words[i]
  const sub2 = words[i + 1]
  if (sub === undefined) return undefined
  if (SELF_MUTATING.has(sub)) return sub
  if (sub === 'engagement' && sub2 !== undefined && SELF_ENGAGEMENT.has(sub2)) {
    return `engagement ${sub2}`
  }
  return undefined
}

/**
 * Final review C1: the commands that acknowledge, create or attest a case are for a person at a
 * terminal. Run from the agent shell they are a write to the case and are denied like one. Review
 * of 2026-10-19: by any launcher, wrapper, runtime or inline script, so every word of the segment
 * is tried as the binary (`npx -p … engagement-guard ack`, `yarn engagement-guard ack`,
 * `unbuffer engagement-guard ack`, `deno run -A dist/cli/bin.js ack`), and every word is searched
 * for the binary and subcommand inside it.
 */
function selfCliHit(seg: SegmentAnalysis): ProtectedHit | undefined {
  const cmd = commandOf(seg)
  if (cmd === undefined) return undefined
  const words = [cmd.program, ...cmd.args]
  const rule = 'guard attestation commands (a person runs them at a terminal; never the agent)'
  for (let i = 0; i < words.length; i++) {
    const w = words[i] as string
    if (namesSelf(w)) {
      const sub = mutatingAt(words, i + 1)
      if (sub !== undefined) return { rule, path: `engagement-guard ${sub}` }
    }
    const inline = SELF_INLINE.exec(w)
    if (inline !== null) return { rule, path: inline[0].trim() }
  }
  return undefined
}

function scanAnalysis(a: CommandAnalysis, s: Scan, start: string | null, out: ScanResult): void {
  let dir = start
  for (const seg of a.segments) {
    const self = selfCliHit(seg)
    if (self !== undefined) {
      out.certain = self
      return
    }
    const effects = effectsOf(seg)
    if (effects.length > 0) out.writes = true
    for (const e of effects) {
      const hit = check(s, dir, e, false)
      if (hit?.possible === true) out.possible ??= hit
      else if (hit !== undefined) {
        out.certain = hit
        return
      }
    }
    if (seg.nested) {
      scanAnalysis(seg.nested, s, dir, out)
      if (out.certain !== undefined) return
    }
    const next = cdTarget(seg, s, dir)
    if (next !== undefined) dir = next
  }
}

/**
 * A Write/Edit to `file` (absolute, or relative to the cwd) that lands on a protected path or
 * replaces the directory of a protected file. The path is literal: `$` is not an expansion.
 */
export function protectedFileHit(file: string, scope: ProtectedScope): ProtectedHit | undefined {
  const s = scanFor(scope)
  const hit = check(s, scope.cwd, { kind: 'into', raw: file, sources: [], contents: false }, true)
  return hit?.possible === true ? undefined : hit
}

/**
 * The first write, removal, rename, link or copy into a protected path in a shell command; a
 * `possible` hit (an archive extracted into an ancestor) only when nothing certain was found.
 */
export function protectedCommandHit(
  a: CommandAnalysis,
  scope: ProtectedScope,
): ProtectedHit | undefined {
  const s = scanFor(scope)
  const r: ScanResult = { writes: false }
  scanAnalysis(a, s, scope.cwd, r)
  if (r.certain !== undefined) return r.certain
  if (a.shell === 'powershell') {
    // The PowerShell tokenizer drops `\` separators (`.guard\engagement.yaml` reads as one word),
    // so judge the raw text: a protected name plus anything that writes is a hit (fix round 2, I2).
    const text = fold(a.command)
    const named =
      s.markers.some((m) => text.includes(m)) ||
      s.roots.some((root) => root.forms.some((f) => text.includes(f.root))) ||
      s.dirComponent.test(text)
    if (named && (r.writes || PS_WRITER_TEXT.test(a.command))) {
      return { rule: 'protected case paths (PowerShell text)', path: a.command }
    }
  }
  return r.possible
}
