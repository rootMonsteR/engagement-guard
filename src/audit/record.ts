import { z } from 'zod'
import { canonicalJson, sha256Hex } from '../canonical.js'
import { REASON_CODES, TierSchema } from '../policy/decisions.js'

/** Audit record kinds (spec §6.6). */
export const AUDIT_KINDS = [
  'session.start',
  'session.end',
  'decision',
  'answer',
  'permission',
  'tool.call',
  'exec.spawn',
  'exec.exit',
  'tool.result',
  'case.activate',
  'case.freeze',
  'case.edit',
  'ack.first-run',
  'audit.export',
  'audit.degraded',
] as const

export const AuditTargetSchema = z.object({
  raw: z.string(),
  class: z.string(),
  rule: z.string().nullable(),
  resolved: z.array(z.string()),
})

const StreamDigestSchema = z.object({ sha256: z.string(), bytes: z.number() })

/** One line of the append-only, hash-chained audit log (spec §6.6). */
export const AuditRecordSchema = z.strictObject({
  v: z.literal(1),
  seq: z.number().int().nonnegative(),
  /** ISO-8601 wall-clock time. */
  ts: z.string(),
  /** Milliseconds since process start (monotonic; spec §10 clock trust). */
  mono: z.number(),
  operator: z.string(),
  caseId: z.string(),
  sessionId: z.string(),
  kind: z.enum(AUDIT_KINDS),
  callId: z.string().nullable(),
  /** Null until subagents (M6). */
  parentCallId: z.string().nullable(),
  tool: z.string().nullable(),
  command: z.string().nullable(),
  targets: z.array(AuditTargetSchema),
  scope: z
    .object({
      verdict: z.enum(['deny', 'ask', 'ask-unskippable', 'pass']),
      reason: z.enum(REASON_CODES),
      tier: TierSchema.nullable(),
    })
    .nullable(),
  permission: z
    .object({
      kind: z.enum(['allow', 'deny', 'ask']),
      source: z.string(),
      reason: z.string().nullable(),
    })
    .nullable(),
  exec: z
    .object({
      backend: z.string(),
      exitCode: z.number().nullable(),
      durationMs: z.number(),
      timedOut: z.boolean(),
      stdout: StreamDigestSchema.nullable(),
      stderr: StreamDigestSchema.nullable(),
      artifactDir: z.string().nullable(),
    })
    .nullable(),
  data: z.record(z.string(), z.unknown()).nullable(),
  prevHash: z.string().regex(/^[0-9a-f]{64}$/),
  hash: z.string().regex(/^[0-9a-f]{64}$/),
})
export type AuditRecord = z.infer<typeof AuditRecordSchema>

/** `prevHash` of the first record in a case+session chain. */
export function genesisHash(caseId: string, sessionId: string): string {
  return sha256Hex(`guard-audit-v1:${caseId}:${sessionId}`)
}

/** `sha256(canonicalJson(record sans hash))`; a `hash` field on the argument is ignored. */
export function hashRecord(rec: Omit<AuditRecord, 'hash'>): string {
  const { hash: _hash, ...rest } = rec as Omit<AuditRecord, 'hash'> & { hash?: unknown }
  return sha256Hex(canonicalJson(rest))
}
