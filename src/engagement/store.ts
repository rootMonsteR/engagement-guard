import { mkdir, readdir, readFile, rm, stat } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { parseDocument, Scalar, YAMLMap } from 'yaml'
import type { AuditLog, AuditRecordInput } from '../audit/writer.js'
import { canonicalJson, sha256Hex } from '../canonical.js'
import {
  ATTESTATION_STATEMENT_VERSION,
  loadFirstRunAck,
  readAttestationStatement,
} from '../first-run.js'
import { isMissing, writeFileAtomic } from '../fs-util.js'
import { DEFAULT_COMMAND_HINT, DEFAULT_DIR, type GuardPaths } from '../paths.js'
import { type DiffEntry, diffValues, renderDiff } from './diff.js'
import {
  ENGAGEMENT_PATH,
  type LoadedCase,
  type LoadResult,
  loadEngagement,
  parseEngagement,
  scopeHashInput,
  type ValidationIssue,
} from './load.js'

/**
 * The case lifecycle (spec §6.2, §6.11): which case is loaded and whether network actions may use
 * it. A case is `active` only with a first-run acknowledgement, a valid file, `acknowledged_by` and
 * `frozen` both present, and `frozen.scope_hash` equal to the hash of the file as it is now.
 * Attesting is freezing; a later change to the hashed part of the file makes the case `tampered`
 * until an audited edit (`engagement-guard engagement edit`) attests the change, with its diff, in
 * the audit log.
 */
export type CaseState =
  | { status: 'first-run-required' }
  | { status: 'none' }
  | { status: 'invalid'; path: string; issues: ValidationIssue[] }
  | { status: 'unacknowledged'; case: LoadedCase }
  | { status: 'tampered'; case: LoadedCase; frozenHash: string; reason: TamperReason }
  | { status: 'active'; case: LoadedCase }

/**
 * Why a frozen case is not active. `frozenHash` is the hash it was last attested at.
 * - `scope-changed`: `frozen.scope_hash` differs from the hash of the file as it is now.
 * - `attestation-removed`: `frozen` is present but `acknowledged_by` is not.
 * - `unfrozen`: the `frozen` block is gone but the case id has attested snapshots (ruling P25).
 * - `superseded`: `frozen` names an older attested hash than the latest one (an un-audited
 *   revert to an earlier scope).
 */
export type TamperReason = 'scope-changed' | 'attestation-removed' | 'unfrozen' | 'superseded'

/** Who attested a case, against which statement, when and where. */
export interface Attestation {
  operator: string
  statementVersion: string
  /** ISO-8601. */
  at: string
  hostFingerprint: string
}

/** Whether the snapshot of the previously frozen scope could be used as the base of a diff. */
export type SnapshotStatus = 'verified' | 'unavailable' | 'altered'

/** The diff a pending edit would attest. */
export interface PendingEdit {
  /** The hash the case was frozen at. */
  oldHash: string
  /** The hash of the file as it is now. */
  newHash: string
  base: SnapshotStatus
  /** `null` when the base snapshot is unavailable or altered. */
  entries: DiffEntry[] | null
  /** Rendered for the operator; `BASE_UNAVAILABLE` when `entries` is null. */
  diff: string
}

export interface EditResult extends PendingEdit {
  state: CaseState
}

export type CaseLifecycleCode =
  | 'FIRST_RUN_REQUIRED'
  | 'NO_ACTIVE_CASE'
  | 'CASE_INVALID'
  | 'NOT_ACKNOWLEDGED'
  | 'SCOPE_TAMPERED'
  /** The case file changed while it was being attested; nothing was written. */
  | 'CASE_CHANGED'

/** A lifecycle operation refused for the case's current state; `state` is that state. */
export class CaseLifecycleError extends Error {
  constructor(
    readonly code: CaseLifecycleCode,
    message: string,
    readonly state: CaseState,
  ) {
    super(message)
    this.name = 'CaseLifecycleError'
  }
}

export interface CaseStore {
  readonly cwd: string
  /** The home holding the first-run acknowledgement (`GuardPaths.home`). */
  readonly home: string
  /** Whether freeze/edit/activation are written to an audit log. */
  readonly audited: boolean
  /** The state as of the last reload, freeze or edit (no file watching). */
  state(): CaseState
  /** Re-reads the first-run acknowledgement and the case file. */
  reload(): Promise<CaseState>
  /**
   * Attests and freezes an unacknowledged case: writes `acknowledged_by` and `frozen` into the
   * file (comments kept), snapshots the frozen scope and records `case.freeze`. A no-op on an
   * active case; a tampered case must go through `edit`. `expectHash` pins the hash the operator
   * was shown: when the file no longer has it, nothing is written (`CASE_CHANGED`).
   */
  freeze(a: Attestation, opts?: { expectHash?: string }): Promise<CaseState>
  /** The diff `edit` would attest, without writing anything. */
  pendingDiff(): Promise<PendingEdit>
  /**
   * Re-attests a frozen (tampered or active) case: diffs the snapshot frozen at the old hash
   * against the file, re-freezes it at the new hash and records `case.edit` with the diff.
   * `expectNewHash` pins the hash whose diff the operator was shown (`CASE_CHANGED` otherwise).
   */
  edit(a: Attestation, opts?: { expectNewHash?: string }): Promise<EditResult>
  /** Called after every change of state; returns the unsubscribe function. */
  onChange(fn: (s: CaseState) => void): () => void
}

/** Recorded (and shown) instead of a diff when the base snapshot cannot be trusted. */
export const BASE_UNAVAILABLE = '(base snapshot unavailable or altered)'

/** The default frozen scope snapshots directory, relative to the workspace root (`GuardPaths.casesDir`). */
export const CASE_SNAPSHOT_DIR = `${DEFAULT_DIR}/cases`

/** `<cwd>/<casesDir>/<caseId>/<scopeHash>.json` (default `.guard/cases`). */
export function scopeSnapshotPath(
  cwd: string,
  caseId: string,
  scopeHash: string,
  casesDir: string = CASE_SNAPSHOT_DIR,
): string {
  return join(cwd, ...casesDir.split('/'), caseId, `${scopeHash}.json`)
}

const snapshotRef = (casesDir: string, caseId: string, scopeHash: string) =>
  `${casesDir}/${caseId}/${scopeHash}.json`

const BOM = String.fromCharCode(0xfeff)
const stripBom = (text: string) => (text.startsWith(BOM) ? text.slice(1) : text)

/** The leaf names under `GuardPaths.home` that are protected: the acknowledgement and the keys. */
export const PROTECTED_HOME_ENTRIES = ['first-run.json', 'keys'] as const

/**
 * The paths a model must never write (ruling P24), as forward-slash globs for the guard: the
 * workspace's case file, scope snapshots and audit log (`paths`, relative to `cwd`), and the
 * home's acknowledgement (`<home>/first-run.json`) and keys (`<home>/keys`).
 */
export function protectedCasePaths(cwd: string, paths: GuardPaths): string[] {
  const norm = (p: string) => p.replace(/\\/g, '/').replace(/\/+$/, '')
  const w = norm(cwd)
  const h = norm(paths.home)
  return [
    `${w}/${norm(paths.engagementPath)}`,
    `${w}/${norm(paths.casesDir)}/**`,
    `${w}/${norm(paths.auditDir)}/**`,
    `${h}/first-run.json`,
    `${h}/keys/**`,
  ]
}

/** `<cwd>/<casesDir>/<caseId>/HEAD`: the hash the case was last attested at. */
const headPath = (cwd: string, casesDir: string, caseId: string) =>
  join(cwd, ...casesDir.split('/'), caseId, 'HEAD')

const HEX64 = /^[0-9a-f]{64}$/
const SNAPSHOT_NAME = /^([0-9a-f]{64})\.json$/

/** What earlier attestations of a case id left behind under `<casesDir>/<id>/`. */
interface Prior {
  /** The hash in `HEAD`, written by every freeze and edit. */
  head?: string
  /** The most recently modified snapshot, for a case whose `HEAD` is gone. */
  newest?: string
}

async function readPrior(cwd: string, casesDir: string, caseId: string): Promise<Prior> {
  const prior: Prior = {}
  try {
    const head = (await readFile(headPath(cwd, casesDir, caseId), 'utf8')).trim()
    if (HEX64.test(head)) prior.head = head
  } catch (err) {
    if (!isMissing(err)) throw err
  }
  let names: string[]
  try {
    names = await readdir(dirname(headPath(cwd, casesDir, caseId)))
  } catch (err) {
    if (isMissing(err)) return prior
    throw err
  }
  let newestTime = -1
  for (const name of names.sort()) {
    const m = SNAPSHOT_NAME.exec(name)
    if (!m) continue
    const { mtimeMs } = await stat(join(dirname(headPath(cwd, casesDir, caseId)), name))
    if (mtimeMs > newestTime) {
      newestTime = mtimeMs
      prior.newest = m[1] as string
    }
  }
  return prior
}

/**
 * The case state of a load result, assuming the first-run acknowledgement is present. A `frozen`
 * block makes the case frozen whatever `acknowledged_by` says: it is active only when both blocks
 * are present, the hash matches, and no later attestation superseded it. Without `frozen`, a case
 * id with earlier attestations is an un-audited unfreeze (P25); only a fresh id is unacknowledged.
 */
function classify(load: LoadResult, prior: Prior): CaseState {
  if (!load.ok) {
    return load.reason === 'missing'
      ? { status: 'none' }
      : { status: 'invalid', path: load.path, issues: load.issues }
  }
  const c = load.case
  const { frozen, acknowledged_by } = c.engagement
  const tampered = (frozenHash: string, reason: TamperReason): CaseState => ({
    status: 'tampered',
    case: c,
    frozenHash,
    reason,
  })
  if (frozen !== undefined) {
    if (frozen.scope_hash !== c.scopeHash) return tampered(frozen.scope_hash, 'scope-changed')
    if (acknowledged_by === undefined) return tampered(frozen.scope_hash, 'attestation-removed')
    if (prior.head !== undefined && prior.head !== frozen.scope_hash) {
      return tampered(prior.head, 'superseded')
    }
    return { status: 'active', case: c }
  }
  const last = prior.head ?? prior.newest
  if (last !== undefined) return tampered(last, 'unfrozen')
  return { status: 'unacknowledged', case: c }
}

/** The case state of a load result, reading the case id's attestation history from disk. */
async function caseStateOf(cwd: string, casesDir: string, load: LoadResult): Promise<CaseState> {
  const prior = load.ok ? await readPrior(cwd, casesDir, load.case.engagement.id) : {}
  return classify(load, prior)
}

/** Identity of a state for change notification. */
function stateKey(s: CaseState): string {
  switch (s.status) {
    case 'first-run-required':
    case 'none':
      return s.status
    case 'invalid':
      return `invalid:${s.path}:${canonicalJson(s.issues)}`
    case 'tampered':
      return `tampered:${s.reason}:${s.case.engagement.id}:${s.case.scopeHash}:${s.frozenHash}`
    case 'unacknowledged':
    case 'active':
      return `${s.status}:${s.case.engagement.id}:${s.case.scopeHash}`
  }
}

function quoted(value: string): Scalar {
  const node = new Scalar(value)
  node.type = Scalar.QUOTE_DOUBLE
  return node
}

/**
 * `text` with `acknowledged_by` and `frozen` set (replaced in place when present), editing the
 * YAML document so the operator's comments, key order and flow style survive. Hex values are
 * quoted: an all-digit hash would otherwise read back as a number. Keeps a BOM and CRLF endings.
 */
function withAttestation(text: string, a: Attestation, scopeHash: string): string {
  const bom = text.startsWith(BOM)
  const body = stripBom(text)
  const doc = parseDocument(body, { logLevel: 'error' })
  if (doc.errors.length > 0) throw new Error(`cannot edit the case file: ${doc.errors[0]?.message}`)
  const ack = new YAMLMap<string, unknown>()
  ack.set('operator', a.operator)
  ack.set('at', a.at)
  ack.set('statement_version', a.statementVersion)
  ack.set('host_fingerprint', quoted(a.hostFingerprint))
  const frozen = new YAMLMap<string, unknown>()
  frozen.set('at', a.at)
  frozen.set('by', a.operator)
  frozen.set('scope_hash', quoted(scopeHash))
  doc.set('acknowledged_by', ack)
  doc.set('frozen', frozen)
  let out = doc.toString({ lineWidth: 0, flowCollectionPadding: false })
  if (body.includes('\r\n')) out = out.replace(/\r?\n/g, '\r\n')
  return bom ? `${BOM}${out}` : out
}

type Base = { status: 'verified'; value: unknown } | { status: 'unavailable' | 'altered' }

/** The snapshot frozen at `scopeHash`, trusted only when its sha256 is that hash. */
async function readSnapshot(
  cwd: string,
  casesDir: string,
  caseId: string,
  scopeHash: string,
): Promise<Base> {
  let text: string
  try {
    text = await readFile(scopeSnapshotPath(cwd, caseId, scopeHash, casesDir), 'utf8')
  } catch {
    return { status: 'unavailable' }
  }
  if (sha256Hex(text) !== scopeHash) return { status: 'altered' }
  try {
    return { status: 'verified', value: JSON.parse(text) }
  } catch {
    return { status: 'altered' }
  }
}

/**
 * Writes the canonical JSON of the hashed part of the case (its sha256 is the scope hash).
 * Returns whether this call created the file (an identical existing snapshot is left alone).
 */
async function writeSnapshot(cwd: string, casesDir: string, loaded: LoadedCase): Promise<boolean> {
  const { id } = loaded.engagement
  const content = canonicalJson(scopeHashInput(loaded.engagement))
  if (sha256Hex(content) !== loaded.scopeHash) {
    throw new Error('internal: the scope snapshot does not hash to the scope hash')
  }
  const path = scopeSnapshotPath(cwd, id, loaded.scopeHash, casesDir)
  // Only a missing file counts as "absent"; any other read failure aborts the operation rather
  // than risking the later clean-up deleting a snapshot that really existed.
  const existing = await readFile(path, 'utf8').catch((err: unknown) => {
    if (isMissing(err)) return undefined
    throw err
  })
  if (existing === content) return false
  await mkdir(dirname(path), { recursive: true })
  await writeFileAtomic(path, content)
  return existing === undefined
}

type FrozenOrNot = Extract<CaseState, { status: 'unacknowledged' | 'tampered' | 'active' }>

/**
 * The case store. The initial `reload()` happens before this resolves. `audit` is optional
 * (ruling P11): without it freeze/edit still work but are not recorded (`audited` is false).
 * `engagementPath` and `casesDir` are relative to `cwd` (`GuardPaths`; default `.guard/…`).
 */
export async function createCaseStore(opts: {
  cwd: string
  home: string
  audit?: AuditLog
  now?: () => Date
  engagementPath?: string
  casesDir?: string
}): Promise<CaseStore> {
  const { cwd, home, audit } = opts
  const now = opts.now ?? (() => new Date())
  const engagementPath = opts.engagementPath ?? ENGAGEMENT_PATH
  const casesDir = opts.casesDir ?? CASE_SNAPSHOT_DIR
  const casePath = join(cwd, engagementPath)
  let current: CaseState = { status: 'none' }
  /** `<id>:<hash>` of the last `case.activate` record; cleared when the case stops being active. */
  let activated: string | undefined
  const listeners = new Set<(s: CaseState) => void>()
  let queue: Promise<unknown> = Promise.resolve()

  /** Runs lifecycle operations one at a time. */
  function serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = queue.then(fn)
    queue = run.catch(() => {})
    return run
  }

  /**
   * Moves to `next`: records `case.activate` when a case (id + hash) becomes active, then
   * notifies listeners if the state changed. A failed audit write rejects, after notifying (the
   * audit log is then degraded and the guard denies).
   */
  async function commit(next: CaseState): Promise<CaseState> {
    const changed = stateKey(current) !== stateKey(next)
    current = next
    try {
      if (next.status !== 'active') {
        activated = undefined
      } else {
        const { engagement, scopeHash } = next.case
        const key = `${engagement.id}:${scopeHash}`
        if (activated !== key && audit !== undefined) {
          audit.setCase(engagement.id)
          await audit.append({
            kind: 'case.activate',
            data: {
              scopeHash,
              frozenAt: engagement.frozen?.at ?? null,
              frozenBy: engagement.frozen?.by ?? null,
            },
          })
        }
        // Marked only once recorded, so a failed write is retried by the next reload.
        activated = key
      }
    } finally {
      if (changed) notify(next)
    }
    return next
  }

  function notify(s: CaseState): void {
    for (const fn of [...listeners]) {
      try {
        fn(s)
      } catch {
        // A listener's failure is its own; the store has already moved to `s`.
      }
    }
  }

  async function reloadNow(): Promise<CaseState> {
    const ack = await loadFirstRunAck(home)
    const load = await loadEngagement(cwd, { now: now(), engagementPath })
    return commit(
      ack === undefined ? { status: 'first-run-required' } : await caseStateOf(cwd, casesDir, load),
    )
  }

  /**
   * Reads the case for a freeze or edit, commits the state it is in, and refuses unless the
   * first-run acknowledgement is present and the file is valid.
   */
  async function readForChange(): Promise<{ text: string; state: FrozenOrNot }> {
    const ack = await loadFirstRunAck(home)
    let text: string | undefined
    try {
      text = await readFile(casePath, 'utf8')
    } catch (err) {
      if (!isMissing(err)) throw err
    }
    const load: LoadResult =
      text === undefined
        ? { ok: false, path: casePath, reason: 'missing', issues: [] }
        : parseEngagement(stripBom(text), casePath, { now: now() })
    const caseState = await caseStateOf(cwd, casesDir, load)
    const state = await commit(ack === undefined ? { status: 'first-run-required' } : caseState)
    if (state.status === 'first-run-required') {
      throw new CaseLifecycleError(
        'FIRST_RUN_REQUIRED',
        'the operator acknowledgement is missing or out of date: acknowledge it first (engagement-guard ack)',
        state,
      )
    }
    if (state.status === 'none' || text === undefined) {
      throw new CaseLifecycleError(
        'NO_ACTIVE_CASE',
        `no case file at ${casePath}: run engagement-guard init`,
        state,
      )
    }
    if (state.status === 'invalid') {
      throw new CaseLifecycleError(
        'CASE_INVALID',
        `the case file is invalid: run engagement-guard engagement validate`,
        state,
      )
    }
    return { text, state }
  }

  async function pendingOf(loaded: LoadedCase, oldHash: string): Promise<PendingEdit> {
    const base = await readSnapshot(cwd, casesDir, loaded.engagement.id, oldHash)
    const newHash = loaded.scopeHash
    if (base.status !== 'verified') {
      return { oldHash, newHash, base: base.status, entries: null, diff: BASE_UNAVAILABLE }
    }
    const entries = diffValues(base.value, scopeHashInput(loaded.engagement))
    return { oldHash, newHash, base: 'verified', entries, diff: renderDiff(entries) }
  }

  async function attestationData(a: Attestation): Promise<Record<string, unknown>> {
    const statement = await readAttestationStatement()
    return {
      ...a,
      statementSha256:
        a.statementVersion === ATTESTATION_STATEMENT_VERSION ? statement.sha256 : null,
    }
  }

  /**
   * Rewrites the case file attested at its current hash: validate the new text, re-check the file
   * did not change meanwhile, record (synced), and only then write the snapshot, replace the file
   * and move HEAD, so an audit failure leaves the case as it was. A failure between the two
   * writes leaves a frozen hash HEAD does not name (`superseded`), which another edit fixes.
   */
  async function writeAttested(
    text: string,
    loaded: LoadedCase,
    a: Attestation,
    record: (snapshot: string) => Promise<AuditRecordInput>,
  ): Promise<CaseState> {
    const next = withAttestation(text, a, loaded.scopeHash)
    const check = parseEngagement(stripBom(next), casePath, { now: now() })
    // Once written, HEAD names this hash, so the rewritten file must classify as active with it.
    const checked = classify(check, { head: loaded.scopeHash })
    if (checked.status !== 'active' || checked.case.scopeHash !== loaded.scopeHash) {
      throw new Error('internal: the attested case file does not validate as active')
    }
    const snapshot = snapshotRef(casesDir, loaded.engagement.id, loaded.scopeHash)
    const onDisk = await readFile(casePath, 'utf8').catch(() => undefined)
    if (onDisk !== text) {
      throw new CaseLifecycleError(
        'CASE_CHANGED',
        'the case file changed while it was being attested; nothing was written, try again',
        current,
      )
    }
    if (audit !== undefined) {
      audit.setCase(loaded.engagement.id)
      await audit.append(await record(snapshot), { sync: true })
    }
    // The snapshot is attestation history (readPrior), so it is written only once the attestation
    // is recorded, and removed again if this call created it and the case file was not replaced:
    // a refused or failed operation leaves none behind. A crash between the record and the rename
    // leaves the case as it was (retryable) plus an audit record that took no effect.
    const created = await writeSnapshot(cwd, casesDir, loaded)
    let replaced = false
    try {
      const mode = (await stat(casePath)).mode & 0o777
      await writeFileAtomic(casePath, next, mode)
      replaced = true
      await writeFileAtomic(headPath(cwd, casesDir, loaded.engagement.id), `${loaded.scopeHash}\n`)
    } catch (err) {
      // After the rename the snapshot is the frozen file's real history: keep it. A stale HEAD
      // then reads as `superseded` (for an edit), which another edit repairs.
      if (created && !replaced) {
        // Best effort: a failed clean-up must never replace the original error.
        await rm(scopeSnapshotPath(cwd, loaded.engagement.id, loaded.scopeHash, casesDir), {
          force: true,
        }).catch(() => undefined)
      }
      throw err
    }
    return commit(checked)
  }

  /** Refuses with CASE_CHANGED when the case no longer has the hash the operator was shown. */
  function pin(state: FrozenOrNot, expected: string | undefined): void {
    if (expected === undefined || state.case.scopeHash === expected) return
    throw new CaseLifecycleError(
      'CASE_CHANGED',
      `the case file changed after it was shown (scope_hash ${expected.slice(0, 12)} → ${state.case.scopeHash.slice(0, 12)}); nothing was written: review it and attest again`,
      state,
    )
  }

  /** The hash a frozen case was frozen at; an unacknowledged case has none to edit from. */
  function frozenHashOf(state: FrozenOrNot): string {
    if (state.status === 'unacknowledged') {
      throw new CaseLifecycleError(
        'NOT_ACKNOWLEDGED',
        `${state.case.engagement.id} is not frozen yet: attest it with engagement-guard engagement freeze`,
        state,
      )
    }
    return state.status === 'tampered' ? state.frozenHash : state.case.scopeHash
  }

  const store: CaseStore = {
    cwd,
    home,
    audited: audit !== undefined,
    state: () => current,
    reload: () => serial(reloadNow),
    freeze: (a, opts = {}) =>
      serial(async () => {
        const { text, state } = await readForChange()
        pin(state, opts.expectHash)
        if (state.status === 'active') return state
        if (state.status === 'tampered') {
          throw new CaseLifecycleError(
            'SCOPE_TAMPERED',
            `${state.case.engagement.id} is frozen and its file changed without an audited edit (${state.reason}): review and attest the change with ${DEFAULT_COMMAND_HINT}`,
            state,
          )
        }
        const loaded = state.case
        return writeAttested(text, loaded, a, async (snapshot) => ({
          kind: 'case.freeze',
          data: { scopeHash: loaded.scopeHash, snapshot, attestation: await attestationData(a) },
        }))
      }),
    pendingDiff: () =>
      serial(async () => {
        const { state } = await readForChange()
        return pendingOf(state.case, frozenHashOf(state))
      }),
    edit: (a, opts = {}) =>
      serial(async () => {
        const { text, state } = await readForChange()
        pin(state, opts.expectNewHash)
        const loaded = state.case
        const pending = await pendingOf(loaded, frozenHashOf(state))
        const next = await writeAttested(text, loaded, a, async (snapshot) => ({
          kind: 'case.edit',
          data: {
            oldHash: pending.oldHash,
            newHash: pending.newHash,
            baseSnapshot: pending.base,
            diff: pending.entries,
            ...(state.status === 'tampered' ? { tamperReason: state.reason } : {}),
            ...(pending.entries === null ? { diffNote: BASE_UNAVAILABLE } : {}),
            snapshot,
            attestation: await attestationData(a),
          },
        }))
        return { ...pending, state: next }
      }),
    onChange(fn) {
      listeners.add(fn)
      return () => {
        listeners.delete(fn)
      }
    },
  }
  await store.reload()
  return store
}
