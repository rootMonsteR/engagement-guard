import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import type { AuditLog } from '../audit/writer.js'
import {
  ATTESTATION_STATEMENT_VERSION,
  hostFingerprint,
  loadFirstRunAck,
  readAttestationStatement,
} from '../first-run.js'
import { DEFAULT_COMMAND_HINT, type GuardPaths, resolvePaths } from '../paths.js'
import type { Prompter } from '../types.js'
import { ENGAGEMENT_PATH, type LoadResult, parseEngagement, type ValidationIssue } from './load.js'
import type { CaseTextHints } from './render.js'
import { CASE_PROFILES, CASE_TYPES, RESERVED_CASE_TYPES } from './schema.js'
import {
  type Attestation,
  CaseLifecycleError,
  type CaseState,
  type CaseStore,
  createCaseStore,
  type TamperReason,
} from './store.js'
import { type ScaffoldOptions, scaffoldEngagement } from './template.js'

/** What a command produced: the text to show (no trailing newline) and the exit code. */
export interface CommandOutcome {
  exitCode: number
  output: string
}

export interface EngagementCommandContext {
  /** The workspace root; relative paths resolve against it. */
  cwd: string
  /** Whether the caller can ask the operator questions (REPL) or not (CLI subcommand, `-p`). */
  interactive: boolean
  ui?: Prompter
  /**
   * The home (`GuardPaths.home`: `GUARD_HOME` resolved by the caller), where the first-run
   * acknowledgement lives. show/freeze/edit/load need it unless `cases` is given.
   */
  home?: string
  /** The session's audit log. Without it freeze/edit still work but are not recorded. */
  audit?: AuditLog
  /** The session's case store (the security layer's); otherwise each command opens its own. */
  cases?: CaseStore
  now?: () => Date
  /**
   * The workspace paths and the attesting command (`GuardPaths`: a guard's `dirName` and
   * `commandHint`): where `new` writes and `validate` reads, the store a command opens, and the
   * names every message uses. Default: `.guard/…` and `engagement-guard engagement edit`.
   */
  paths?: GuardPaths
}

/** The context's paths, or the defaults (no environment is read). */
const pathsOf = (ctx: EngagementCommandContext): GuardPaths =>
  ctx.paths ?? resolvePaths({ env: {} })

const engagementUsage = (
  engagementPath: string,
) => `Usage: engagement <new|validate|show|freeze|edit|load> [options]

  new       Write a commented ${engagementPath} with TODO for every value not given
              --type <${CASE_TYPES.join('|')}>  (default: pentest)
              --profile <${CASE_PROFILES.join('|')}>  (default: external)
              --id <slug> --name <text> --client <text>
              --in <target> (repeatable) --out <target> (repeatable)
              --window-start <date-time> --window-end <date-time> --timezone <IANA zone>
              --auth-ref <text> --authorised-by <text> --signed-on <YYYY-MM-DD>
              --force   overwrite an existing file
  validate  Check the engagement file and list every error and warning
              --file <path>  (default: ${engagementPath})
  show      Print the case status, id, scope_hash, window, scope counts and RoE tiers
  freeze    Attest the case and freeze its scope (shows the attestation statement)
              --attest <caseId>  attest without a prompt (required when non-interactive)
  edit      Attest a change to a frozen case's scope; prints and records the diff
              --attest <caseId>  attest without a prompt (required when non-interactive)
  load      Re-read the case file and the first-run acknowledgement`

const fail = (output: string): CommandOutcome => ({ exitCode: 1, output })
const usageError = (message: string, ctx: EngagementCommandContext): CommandOutcome =>
  fail(`${message}\n${engagementUsage(pathsOf(ctx).engagementPath)}`)

/**
 * The `engagement` command family (`engagement-guard init` / `engagement-guard engagement`, or a
 * host's own command). Never writes to the terminal: the caller prints `output`.
 */
export async function runEngagementCommand(
  argv: string[],
  ctx: EngagementCommandContext,
): Promise<CommandOutcome> {
  const [sub, ...rest] = argv
  switch (sub) {
    case 'new':
      return newCommand(rest, ctx)
    case 'validate':
      return validateCommand(rest, ctx)
    case 'show':
      return showCommand(rest, ctx)
    case 'freeze':
      return freezeCommand(rest, ctx)
    case 'edit':
      return editCommand(rest, ctx)
    case 'load':
      return loadCommand(rest, ctx)
    case '--help':
    case '-h':
    case 'help':
      return { exitCode: 0, output: engagementUsage(pathsOf(ctx).engagementPath) }
    case undefined:
      return usageError('missing subcommand', ctx)
    default:
      return usageError(`unknown subcommand '${sub}'`, ctx)
  }
}

// --- new ----------------------------------------------------------------------------------------

const NEW_OPTIONS = {
  type: { type: 'string' },
  profile: { type: 'string' },
  id: { type: 'string' },
  name: { type: 'string' },
  client: { type: 'string' },
  in: { type: 'string', multiple: true },
  out: { type: 'string', multiple: true },
  'window-start': { type: 'string' },
  'window-end': { type: 'string' },
  timezone: { type: 'string' },
  'auth-ref': { type: 'string' },
  'authorised-by': { type: 'string' },
  'signed-on': { type: 'string' },
  force: { type: 'boolean' },
} as const

const includes = <T extends string>(list: readonly T[], value: string): value is T =>
  (list as readonly string[]).includes(value)

async function newCommand(argv: string[], ctx: EngagementCommandContext): Promise<CommandOutcome> {
  let values: ReturnType<typeof parseNew>['values']
  try {
    values = parseNew(argv).values
  } catch (err) {
    return usageError((err as Error).message, ctx)
  }

  const kind = values.type ?? 'pentest'
  if (includes(RESERVED_CASE_TYPES, kind)) {
    return fail(`CASE_TYPE_NOT_YET_SUPPORTED: ${kind} arrives in a later release`)
  }
  if (!includes(CASE_TYPES, kind)) {
    return fail(`unknown case type '${kind}': expected ${CASE_TYPES.join(' | ')}`)
  }
  const profile = values.profile ?? 'external'
  if (!includes(CASE_PROFILES, profile)) {
    return fail(`unknown profile '${profile}': expected ${CASE_PROFILES.join(' | ')}`)
  }

  const options: ScaffoldOptions = { type: kind, profile }
  const set = <K extends keyof ScaffoldOptions>(key: K, v: ScaffoldOptions[K] | undefined) => {
    if (v !== undefined) options[key] = v
  }
  set('id', values.id)
  set('name', values.name)
  set('client', values.client)
  set('in', values.in)
  set('out', values.out)
  set('windowStart', values['window-start'])
  set('windowEnd', values['window-end'])
  set('timezone', values.timezone)
  set('authReference', values['auth-ref'])
  set('authorisedBy', values['authorised-by'])
  set('signedOn', values['signed-on'])

  const path = join(ctx.cwd, pathsOf(ctx).engagementPath)
  await mkdir(dirname(path), { recursive: true })
  try {
    // `wx` fails if the file exists, so the check and the write cannot race.
    await writeFile(path, scaffoldEngagement(options), { flag: values.force ? 'w' : 'wx' })
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
      return fail(`already exists: ${path} (use --force to overwrite)`)
    }
    throw err
  }
  return {
    exitCode: 0,
    output: `wrote ${path}\nnext: replace every TODO, then run: engagement-guard engagement validate`,
  }
}

function parseNew(argv: string[]) {
  return parseArgs({ args: argv, options: NEW_OPTIONS, allowPositionals: false, strict: true })
}

// --- validate -----------------------------------------------------------------------------------

async function validateCommand(
  argv: string[],
  ctx: EngagementCommandContext,
): Promise<CommandOutcome> {
  let file: string | undefined
  try {
    file = parseArgs({
      args: argv,
      options: { file: { type: 'string' } },
      allowPositionals: false,
      strict: true,
    }).values.file
  } catch (err) {
    return usageError((err as Error).message, ctx)
  }

  const path =
    file === undefined ? join(ctx.cwd, pathsOf(ctx).engagementPath) : resolve(ctx.cwd, file)
  let text: string
  try {
    text = await readFile(path, 'utf8')
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT' || code === 'ENOTDIR') {
      return fail(`missing: ${path} — run: engagement-guard init`)
    }
    throw err
  }
  return report(parseEngagement(text.startsWith('\uFEFF') ? text.slice(1) : text, path))
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`

function report(r: LoadResult): CommandOutcome {
  if (r.ok) {
    const { issues } = r.case
    const head = `valid: ${r.case.engagement.id} (${plural(issues.length, 'warning')})`
    return { exitCode: 0, output: [head, ...sorted(issues).map(issueLine)].join('\n') }
  }
  const errors = r.issues.filter((i) => i.severity === 'error').length
  const warnings = r.issues.length - errors
  const head = `invalid: ${r.path} (${plural(errors, 'error')}, ${plural(warnings, 'warning')})`
  return fail([head, ...sorted(r.issues).map(issueLine)].join('\n'))
}

/** Errors first; otherwise in the order validation reported them. */
const sorted = (issues: ValidationIssue[]): ValidationIssue[] => [
  ...issues.filter((i) => i.severity === 'error'),
  ...issues.filter((i) => i.severity !== 'error'),
]

const issueLine = (i: ValidationIssue): string =>
  `${i.severity} ${i.path === '' ? '(document)' : i.path} ${i.code}: ${i.message}`

// --- case lifecycle: show, freeze, edit, load ----------------------------------------------------

const NOT_AUDITED = '(not audited: no audit log)'

/** The session's store, or one opened for this command; `undefined` without a home. */
async function storeFor(ctx: EngagementCommandContext): Promise<CaseStore | undefined> {
  if (ctx.cases !== undefined) return ctx.cases
  if (ctx.home === undefined) return undefined
  return createCaseStore({
    cwd: ctx.cwd,
    home: ctx.home,
    ...(ctx.audit === undefined ? {} : { audit: ctx.audit }),
    ...(ctx.now === undefined ? {} : { now: ctx.now }),
    ...(ctx.paths === undefined
      ? {}
      : { engagementPath: ctx.paths.engagementPath, casesDir: ctx.paths.casesDir }),
  })
}

const noHome = (sub: string) =>
  fail(`engagement ${sub}: no home was supplied, so the first-run acknowledgement cannot be read`)

/** Parses the options of a lifecycle subcommand: none, or `--attest <caseId>` when `attest`. */
function parseLifecycle(
  argv: string[],
  attest: boolean,
  ctx: EngagementCommandContext,
): { attest?: string } | { error: CommandOutcome } {
  try {
    const { values } = parseArgs({
      args: argv,
      options: attest ? { attest: { type: 'string' } } : {},
      allowPositionals: false,
      strict: true,
    })
    const value = (values as { attest?: string }).attest
    return value === undefined ? {} : { attest: value }
  } catch (err) {
    return { error: usageError((err as Error).message, ctx) }
  }
}

const short = (hash: string) => hash.slice(0, 12)

const TAMPER_TEXT: Record<TamperReason, (id: string) => string> = {
  'scope-changed': (id) => `the scope of ${id} changed since it was frozen`,
  'attestation-removed': (id) => `the acknowledged_by block of frozen case ${id} was removed`,
  unfrozen: (id) => `the frozen block of ${id} was removed without an audited edit`,
  superseded: (id) => `${id} is frozen at an older hash than its latest attestation`,
}

/**
 * One line: the state, what it means for network actions and the command that fixes it. `hints`
 * names the case file and the attesting command of a guard with a custom `dirName` or
 * `commandHint` (default `.guard/engagement.yaml`, `engagement-guard engagement edit`).
 */
export function caseStatusLine(s: CaseState, hints: CaseTextHints = {}): string {
  const engagementPath = hints.engagementPath ?? ENGAGEMENT_PATH
  const commandHint = hints.commandHint ?? DEFAULT_COMMAND_HINT
  const denied = 'network actions are denied'
  switch (s.status) {
    case 'first-run-required':
      return `status: first-run-required — the operator acknowledgement is missing or out of date; ${denied} — run: engagement-guard ack`
    case 'none':
      return `status: none — no ${engagementPath}; ${denied} — run: engagement-guard init`
    case 'invalid': {
      const errors = s.issues.filter((i) => i.severity === 'error').length
      return `status: invalid — ${s.path} (${plural(errors, 'error')}); ${denied} — run: engagement-guard engagement validate`
    }
    case 'unacknowledged':
      return `status: unacknowledged — ${s.case.engagement.id} is not attested; ${denied} — run: engagement-guard engagement freeze`
    case 'tampered':
      return `status: tampered — ${TAMPER_TEXT[s.reason](s.case.engagement.id)} (${short(s.frozenHash)} → ${short(s.case.scopeHash)}); ${denied} — run: ${commandHint}`
    case 'active':
      return `status: active — ${s.case.engagement.id} (scope_hash ${short(s.case.scopeHash)})`
  }
}

/** The status line, followed by the issues of an invalid case. */
function statusReport(s: CaseState, hints: CaseTextHints): string {
  if (s.status !== 'invalid') return caseStatusLine(s, hints)
  return [caseStatusLine(s, hints), ...sorted(s.issues).map(issueLine)].join('\n')
}

function showCommand(argv: string[], ctx: EngagementCommandContext): Promise<CommandOutcome> {
  return lifecycle('show', argv, false, ctx, async (store, _attest, hints) => {
    const s = store.state()
    // A session store is not re-read here (`load` does that): say so.
    const asOf = ctx.cases === undefined ? '' : ' (as of last load)'
    if (s.status === 'first-run-required' || s.status === 'none' || s.status === 'invalid') {
      const [head = '', ...rest] = statusReport(s, hints).split('\n')
      return { exitCode: 0, output: [`${head}${asOf}`, ...rest].join('\n') }
    }
    const { engagement: e, scopeHash } = s.case
    const frozen =
      e.frozen === undefined
        ? 'frozen: no'
        : `frozen: ${e.frozen.at} by ${e.frozen.by} (scope_hash ${e.frozen.scope_hash})`
    const lines = [
      `${caseStatusLine(s, hints)}${asOf}`,
      `id: ${e.id}`,
      `name: ${e.name}`,
      `type: ${e.type} (${e.profile})`,
      `client: ${e.client}`,
      `scope_hash: ${scopeHash}`,
      `window: ${e.window.start} → ${e.window.end} (${e.window.timezone})`,
      `scope: ${e.scope.in.length} in, ${e.scope.out.length} out, ${e.scope.operator_infrastructure.length} operator`,
      `roe tiers: ${e.roe.allowed_test_classes.join(', ')}`,
      frozen,
    ]
    return { exitCode: 0, output: lines.join('\n') }
  })
}

function loadCommand(argv: string[], ctx: EngagementCommandContext): Promise<CommandOutcome> {
  return lifecycle('load', argv, false, ctx, async (store, _attest, hints) => {
    // A store opened for this command has just loaded; the session's store is reloaded.
    const s = ctx.cases === undefined ? store.state() : await store.reload()
    return { exitCode: 0, output: statusReport(s, hints) }
  })
}

function freezeCommand(argv: string[], ctx: EngagementCommandContext): Promise<CommandOutcome> {
  return lifecycle('freeze', argv, true, ctx, async (store, attest, hints) => {
    const s = ctx.cases === undefined ? store.state() : await store.reload()
    if (s.status === 'active') {
      return {
        exitCode: 0,
        output: `already frozen: ${s.case.engagement.id} scope_hash ${s.case.scopeHash}\n${caseStatusLine(s, hints)}`,
      }
    }
    if (s.status === 'tampered') {
      return fail(
        `cannot freeze: ${TAMPER_TEXT[s.reason](s.case.engagement.id)}; review and attest the change with ${hints.commandHint}\n${caseStatusLine(s, hints)}`,
      )
    }
    if (s.status !== 'unacknowledged') return fail(`cannot freeze\n${statusReport(s, hints)}`)

    const id = s.case.engagement.id
    const hash = s.case.scopeHash
    const refused = await confirmAttestation(id, attest, ctx, `Case ${id}, scope_hash ${hash}`)
    if (refused !== undefined) return fail(`${refused}\n${caseStatusLine(s, hints)}`)
    const a = await attestationFor(store, ctx)
    if (a === undefined) {
      return fail(`cannot freeze\n${caseStatusLine(await store.reload(), hints)}`)
    }
    const next = await store.freeze(a, { expectHash: hash })
    return succeed(store, [`frozen: ${id} scope_hash ${hash}`], next, hints)
  })
}

function editCommand(argv: string[], ctx: EngagementCommandContext): Promise<CommandOutcome> {
  return lifecycle('edit', argv, true, ctx, async (store, attest, hints) => {
    const s = ctx.cases === undefined ? store.state() : await store.reload()
    if (s.status === 'unacknowledged') {
      return fail(
        `cannot edit: ${s.case.engagement.id} is not frozen yet; attest it with engagement-guard engagement freeze\n${caseStatusLine(s, hints)}`,
      )
    }
    if (s.status !== 'tampered' && s.status !== 'active') {
      return fail(`cannot edit\n${statusReport(s, hints)}`)
    }

    const id = s.case.engagement.id
    let preface: string | undefined
    let expectNewHash = s.case.scopeHash
    if (attest === undefined && canAsk(ctx)) {
      const pending = await store.pendingDiff()
      expectNewHash = pending.newHash
      preface = `Changes since ${id} was frozen (scope_hash ${short(pending.oldHash)} → ${short(pending.newHash)}):\n${pending.diff}`
    }
    const refused = await confirmAttestation(id, attest, ctx, preface)
    if (refused !== undefined) return fail(`${refused}\n${caseStatusLine(s, hints)}`)
    const a = await attestationFor(store, ctx)
    if (a === undefined) {
      return fail(`cannot edit\n${caseStatusLine(await store.reload(), hints)}`)
    }
    const r = await store.edit(a, { expectNewHash })
    return succeed(
      store,
      [`attested: ${id} scope_hash ${short(r.oldHash)} → ${short(r.newHash)}`, r.diff],
      r.state,
      hints,
    )
  })
}

/** Common shape: parse options, open the store, map every failure to exit 1. */
async function lifecycle(
  sub: string,
  argv: string[],
  attest: boolean,
  ctx: EngagementCommandContext,
  body: (
    store: CaseStore,
    attest: string | undefined,
    hints: Required<CaseTextHints>,
  ) => Promise<CommandOutcome>,
): Promise<CommandOutcome> {
  const parsed = parseLifecycle(argv, attest, ctx)
  if ('error' in parsed) return parsed.error
  const { engagementPath, commandHint } = pathsOf(ctx)
  const hints = { engagementPath, commandHint }
  try {
    const store = await storeFor(ctx)
    if (store === undefined) return noHome(sub)
    return await body(store, parsed.attest, hints)
  } catch (err) {
    if (err instanceof CaseLifecycleError) {
      return fail(`cannot ${sub}: ${err.message}\n${statusReport(err.state, hints)}`)
    }
    // Audit write failures, unreadable or read-only files, internal checks: report, never throw.
    return fail(`cannot ${sub}: ${err instanceof Error ? err.message : String(err)}`)
  }
}

function succeed(
  store: CaseStore,
  lines: string[],
  s: CaseState,
  hints: CaseTextHints,
): CommandOutcome {
  return {
    exitCode: 0,
    output: [...lines, ...(store.audited ? [] : [NOT_AUDITED]), caseStatusLine(s, hints)].join(
      '\n',
    ),
  }
}

const canAsk = (
  ctx: EngagementCommandContext,
): ctx is EngagementCommandContext & { ui: Prompter } => ctx.interactive && ctx.ui !== undefined

/**
 * Confirms the operator attests case `id`: `--attest <id>` must name it; otherwise an interactive
 * session shows the attestation statement (and `preface`, e.g. the pending diff) and asks for the
 * case id. Returns the reason when not attested.
 */
async function confirmAttestation(
  id: string,
  attest: string | undefined,
  ctx: EngagementCommandContext,
  preface?: string,
): Promise<string | undefined> {
  if (attest !== undefined) {
    return attest === id ? undefined : `not attested: '${attest}' is not the case id (${id})`
  }
  if (!canAsk(ctx)) {
    return `not attested: this session cannot ask; pass --attest ${id} to attest ${id}`
  }
  const statement = await readAttestationStatement()
  const question = [
    statement.text.trimEnd(),
    ...(preface === undefined ? [] : [preface]),
    `Type the case id to attest (${id}); anything else cancels.`,
  ].join('\n\n')
  let answer: string
  try {
    answer = await ctx.ui.askUser({ question })
  } catch (err) {
    return `not attested: ${(err as Error).message}`
  }
  return answer.trim() === id ? undefined : 'not attested: the answer was not the case id'
}

/** The attestation by the operator who gave the first-run acknowledgement; `undefined` without one. */
async function attestationFor(
  store: CaseStore,
  ctx: EngagementCommandContext,
): Promise<Attestation | undefined> {
  const ack = await loadFirstRunAck(store.home)
  if (ack === undefined) return undefined
  return {
    operator: ack.operator,
    statementVersion: ATTESTATION_STATEMENT_VERSION,
    at: (ctx.now?.() ?? new Date()).toISOString(),
    hostFingerprint: hostFingerprint(),
  }
}
