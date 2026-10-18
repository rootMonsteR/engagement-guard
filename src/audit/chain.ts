import { splitLines, type VerifyError } from './layout.js'
import { AuditRecordSchema, genesisHash, hashRecord } from './record.js'
import { messageOf } from './util.js'

export interface ChainCheck {
  records: number
  head: string | null
  /** `seq` of the last schema-valid record, -1 when none. */
  lastSeq: number
  errors: VerifyError[]
}

/**
 * Verifies one chain file's text: every line a schema-valid record of this case and session,
 * `seq` counting up from 0, `prevHash` linking to the previous record (the first to
 * `genesisHash`), and `hash` matching the content. After each schema-valid record the expected
 * `seq`/`prevHash` follow that record, so one tampered line yields errors at that line only.
 */
export function verifyChain(text: string, caseId: string, sessionId: string): ChainCheck {
  const errors: VerifyError[] = []
  let expectedSeq = 0
  let prev = genesisHash(caseId, sessionId)
  let records = 0
  let head: string | null = null
  let lastSeq = -1
  const { lines, complete } = splitLines(text)
  lines.forEach((raw, i) => {
    const line = i + 1
    const isTail = !complete && i === lines.length - 1
    let obj: unknown
    try {
      obj = JSON.parse(raw)
    } catch (err) {
      errors.push(
        isTail
          ? { seq: null, line, code: 'TRUNCATED_TAIL', message: 'final line is incomplete' }
          : { seq: null, line, code: 'PARSE_ERROR', message: messageOf(err) },
      )
      return
    }
    const parsed = AuditRecordSchema.safeParse(obj)
    if (!parsed.success) {
      const seq = (obj as { seq?: unknown } | null)?.seq
      errors.push({
        seq: Number.isInteger(seq) ? (seq as number) : null,
        line,
        code: 'SCHEMA',
        message: parsed.error.issues.map((x) => `${x.path.join('.')}: ${x.message}`).join('; '),
      })
      if (isTail) {
        errors.push({
          seq: null,
          line,
          code: 'TRUNCATED_TAIL',
          message: 'final line has no newline',
        })
      }
      return
    }
    const rec = parsed.data
    if (rec.caseId !== caseId || rec.sessionId !== sessionId) {
      errors.push({
        seq: rec.seq,
        line,
        code: 'SCHEMA',
        message: `record belongs to ${rec.caseId}/${rec.sessionId}, not ${caseId}/${sessionId}`,
      })
    }
    if (rec.seq !== expectedSeq) {
      errors.push({
        seq: rec.seq,
        line,
        code: 'SEQ_GAP',
        message: `expected seq ${expectedSeq}, found ${rec.seq}`,
      })
    }
    if (rec.prevHash !== prev) {
      errors.push({
        seq: rec.seq,
        line,
        code: 'PREV_MISMATCH',
        message: 'prevHash does not link to the previous record',
      })
    }
    let actual: string
    try {
      actual = hashRecord(obj as Parameters<typeof hashRecord>[0])
    } catch (err) {
      actual = `unhashable: ${messageOf(err)}`
    }
    if (actual !== rec.hash) {
      errors.push({
        seq: rec.seq,
        line,
        code: 'HASH_MISMATCH',
        message: 'hash does not match the record content',
      })
    }
    records++
    head = rec.hash
    lastSeq = rec.seq
    expectedSeq = rec.seq + 1
    prev = rec.hash
    if (isTail) {
      errors.push({
        seq: rec.seq,
        line,
        code: 'TRUNCATED_TAIL',
        message: 'final line has no newline',
      })
    }
  })
  return { records, head, lastSeq, errors }
}
