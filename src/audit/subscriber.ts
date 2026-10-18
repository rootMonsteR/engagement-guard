import { sha256Hex } from '../canonical.js'
import type { EventSource, GuardEvent } from '../types.js'
import { messageOf } from './util.js'
import type { AuditLog, AuditRecordInput } from './writer.js'

type EventOf<T extends GuardEvent['type']> = Extract<GuardEvent, { type: T }>

/** Per audit log: releases the `tool.call` its subscriber holds for a call (see `releaseHeldCall`). */
const RELEASERS = new WeakMap<AuditLog, (toolUseId: string) => void>()

/**
 * Writes the `tool.call` record the subscriber on `audit` is holding for `toolUseId`, now, if the
 * call is wanted (inspected or a case is active). The guard calls this synchronously after marking a
 * call inspected and before appending its own `decision` record, so the held call lands first (the
 * log serialises appends in call order). A no-op when nothing is held or no subscriber is attached.
 */
export function releaseHeldCall(audit: AuditLog, toolUseId: string): void {
  try {
    RELEASERS.get(audit)?.(toolUseId)
  } catch {
    // never throw into the guard
  }
}

function commandOf(input: unknown): string | null {
  const command = (input as { command?: unknown } | null | undefined)?.command
  return typeof command === 'string' ? command : null
}

/** Decisions the guard made itself: it writes its own `decision` record before returning. */
function isGuardDecision(decision: EventOf<'permission.decision'>['decision']): boolean {
  return decision.annotations !== undefined && 'guard' in decision.annotations
}

/**
 * Audit "after" (spec §6.6): turns agent events into audit records. A call is recorded when a
 * case is active or the guard inspected it; other events (session lifecycle, exec without a
 * tool call) only while a case is active. Since `tool.call` is announced before the guard runs,
 * a not-yet-inspected call is held back and written ahead of the first later event that shows it
 * was inspected (or dropped at its `tool.result`). Records never carry tool output, only its
 * sha256 and size. Nothing here throws into the bus: the first failed write becomes one
 * `onFailure` call and one `audit.degraded` attempt; later failures are silent (the log
 * is degraded and the guard denies). Held calls are dropped at `turn.end`, all bookkeeping at
 * `session.end`. Returns the unsubscribe function. `opts.onFailure`, when given, receives the
 * message of that first failed write (`audit write failed (<kind>): <error>`); a throw from it is
 * swallowed.
 */
export function subscribeAudit(
  events: EventSource,
  audit: AuditLog,
  opts: {
    caseActive: () => boolean
    inspected: (toolUseId: string) => boolean
    onFailure?: (message: string) => void
  },
): () => void {
  /** `tool.call` records waiting to learn whether their call is inspected. */
  const pendingCalls = new Map<string, AuditRecordInput>()
  /** Running commands by execId: `exec.exit` carries neither backend nor (always) the call. */
  const execs = new Map<string, { backend: string; toolUseId: string | undefined }>()

  // A predicate that throws is answered with "record": auditing too much is the safe side.
  const holds = (pred: () => boolean): boolean => {
    try {
      return pred()
    } catch {
      return true
    }
  }
  const caseActive = (): boolean => holds(opts.caseActive)
  const wanted = (toolUseId: string | undefined): boolean =>
    caseActive() ||
    (toolUseId !== undefined && toolUseId !== '' && holds(() => opts.inspected(toolUseId)))

  /** One-shot: a dead disk gives one `onFailure` call and one `audit.degraded` attempt, not a flood. */
  let failureReported = false
  const reportFailure = (rec: AuditRecordInput, err: unknown): void => {
    if (failureReported) return
    failureReported = true
    try {
      opts.onFailure?.(`audit write failed (${rec.kind}): ${messageOf(err)}`)
    } catch {
      // never throw into the bus
    }
    if (rec.kind === 'audit.degraded') return
    try {
      audit
        .append({ kind: 'audit.degraded', data: { failedKind: rec.kind, error: messageOf(err) } })
        .catch(() => {})
    } catch {
      // never throw into the bus
    }
  }

  const write = (rec: AuditRecordInput): void => {
    try {
      audit.append(rec).catch((err: unknown) => reportFailure(rec, err))
    } catch (err) {
      reportFailure(rec, err)
    }
  }

  const releasePending = (toolUseId: string | undefined): void => {
    if (toolUseId === undefined) return
    const rec = pendingCalls.get(toolUseId)
    if (rec === undefined) return
    pendingCalls.delete(toolUseId)
    write(rec)
  }

  const handle = (e: GuardEvent): void => {
    switch (e.type) {
      case 'session.start':
        if (caseActive()) {
          write({
            kind: 'session.start',
            data: { sessionId: e.sessionId, cwd: e.cwd, model: e.model },
          })
        }
        return
      case 'session.end':
        if (caseActive()) write({ kind: 'session.end', data: { sessionId: e.sessionId } })
        pendingCalls.clear()
        execs.clear()
        return
      case 'turn.end':
        // A cancelled turn may never deliver the tool.result that would drop a held call. Execs
        // are kept: a background command outlives its turn and still exits under this session.
        pendingCalls.clear()
        return
      case 'tool.call': {
        const rec: AuditRecordInput = {
          kind: 'tool.call',
          callId: e.toolUseId,
          tool: e.name,
          command: commandOf(e.input),
          data: { summary: e.summary },
        }
        if (wanted(e.toolUseId)) write(rec)
        else pendingCalls.set(e.toolUseId, rec)
        return
      }
      case 'permission.decision': {
        if (!wanted(e.toolUseId)) return
        releasePending(e.toolUseId)
        if (isGuardDecision(e.decision)) return
        const d = e.decision
        write({
          kind: 'permission',
          callId: e.toolUseId === '' ? null : e.toolUseId,
          permission: {
            kind: d.kind,
            source: d.source,
            reason: d.kind === 'ask' ? d.prompt.title : d.reason,
          },
        })
        return
      }
      case 'exec.spawn': {
        execs.set(e.execId, { backend: e.backend, toolUseId: e.toolUseId })
        if (!(e.toolUseId === undefined ? caseActive() : wanted(e.toolUseId))) return
        releasePending(e.toolUseId)
        write({
          kind: 'exec.spawn',
          callId: e.toolUseId ?? null,
          command: e.command,
          exec: {
            backend: e.backend,
            exitCode: null,
            durationMs: 0,
            timedOut: false,
            stdout: null,
            stderr: null,
            artifactDir: null,
          },
          data: { execId: e.execId, cwd: e.cwd },
        })
        return
      }
      case 'exec.exit': {
        const spawn = execs.get(e.execId)
        execs.delete(e.execId)
        const toolUseId = e.toolUseId ?? spawn?.toolUseId
        if (!(toolUseId === undefined ? caseActive() : wanted(toolUseId))) return
        releasePending(toolUseId)
        write({
          kind: 'exec.exit',
          callId: toolUseId ?? null,
          exec: {
            backend: spawn?.backend ?? 'unknown',
            exitCode: e.code,
            durationMs: e.durationMs,
            timedOut: e.timedOut,
            stdout: e.output?.stdout ?? null,
            stderr: e.output?.stderr ?? null,
            artifactDir: null,
          },
          data: { execId: e.execId },
        })
        return
      }
      case 'tool.result': {
        const record = wanted(e.toolUseId)
        if (record) releasePending(e.toolUseId)
        pendingCalls.delete(e.toolUseId)
        if (!record) return
        write({
          kind: 'tool.result',
          callId: e.toolUseId,
          tool: e.name,
          data: {
            isError: e.isError,
            durationMs: e.durationMs,
            contentSha256: sha256Hex(e.content),
            contentBytes: Buffer.byteLength(e.content, 'utf8'),
          },
        })
        return
      }
      default:
        return
    }
  }

  const release = (toolUseId: string): void => {
    if (wanted(toolUseId)) releasePending(toolUseId)
  }
  RELEASERS.set(audit, release)
  const off = events.on('*', (e) => {
    try {
      handle(e)
    } catch {
      // never throw into the bus
    }
  })
  return () => {
    if (RELEASERS.get(audit) === release) RELEASERS.delete(audit)
    off()
  }
}
