import { z } from 'zod'
import { messageOf } from './util.js'

/**
 * On-disk layout of the audit tree (`<cwd>/.guard/audit`, `GuardPaths.auditDir`): `index.jsonl` names every chain
 * file, each `<caseId>/<sessionId>[.<n>].jsonl`. Shared by the writer and the verifier.
 */

export type VerifyErrorCode =
  | 'PARSE_ERROR'
  | 'SCHEMA'
  | 'SEQ_GAP'
  | 'PREV_MISMATCH'
  | 'HASH_MISMATCH'
  | 'TRUNCATED_TAIL'
  | 'MISSING_FILE'
  | 'UNINDEXED_FILE'
  /** Warning only: the index's final line is an unterminated partial write (ruling P14). */
  | 'INDEX_TORN_TAIL'
  /** An export bundle over the size cap (compressed or inflated). */
  | 'BUNDLE_TOO_LARGE'

export interface VerifyError {
  /** The record's `seq` when it could be read. */
  seq: number | null
  /** 1-based line number in the file; 0 for errors about the whole file. */
  line: number
  code: VerifyErrorCode
  message: string
}

export const INDEX_FILE = 'index.jsonl'

/** A case id or session id is one safe path segment. */
export const SAFE_CASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]*$/
export const SAFE_SESSION_ID = /^[A-Za-z0-9_-]+$/

/** The chain file for a case+session; segment `n > 0` is `<sessionId>.<n>.jsonl`. */
export function chainFile(caseId: string, sessionId: string, segment = 0): string {
  return segment === 0 ? `${caseId}/${sessionId}.jsonl` : `${caseId}/${sessionId}.${segment}.jsonl`
}

function isChainFileOf(file: string, caseId: string, sessionId: string): boolean {
  if (file === chainFile(caseId, sessionId)) return true
  const prefix = `${caseId}/${sessionId}.`
  if (!file.startsWith(prefix) || !file.endsWith('.jsonl')) return false
  return /^[1-9][0-9]*$/.test(file.slice(prefix.length, -'.jsonl'.length))
}

/** One line of `index.jsonl`: written once per chain file, before its first record. */
export const IndexEntrySchema = z
  .strictObject({
    caseId: z.string().regex(SAFE_CASE_ID),
    sessionId: z.string().regex(SAFE_SESSION_ID),
    file: z.string(),
    createdAt: z.string(),
  })
  .refine((e) => isChainFileOf(e.file, e.caseId, e.sessionId), {
    message: 'file must be <caseId>/<sessionId>[.<n>].jsonl',
  })
export type IndexEntry = z.infer<typeof IndexEntrySchema>

/** Splits JSONL text into lines; `complete` is false when the last line has no `\n`. */
export function splitLines(text: string): { lines: string[]; complete: boolean } {
  if (text === '') return { lines: [], complete: true }
  const parts = text.split('\n')
  const complete = text.endsWith('\n')
  return { lines: complete ? parts.slice(0, -1) : parts, complete }
}

/**
 * Parses `index.jsonl`. Malformed lines are errors and a second entry for a file is rejected.
 * An unterminated, unparseable final line is a torn write: a warning (`INDEX_TORN_TAIL`), not an
 * error, since every index entry is self-describing and the writer repairs it on its next open.
 */
export function parseIndex(text: string): {
  entries: IndexEntry[]
  errors: VerifyError[]
  warnings: VerifyError[]
} {
  const entries: IndexEntry[] = []
  const errors: VerifyError[] = []
  const warnings: VerifyError[] = []
  const seen = new Set<string>()
  const { lines, complete } = splitLines(text)
  lines.forEach((raw, i) => {
    const line = i + 1
    let obj: unknown
    try {
      obj = JSON.parse(raw)
    } catch (err) {
      if (!complete && i === lines.length - 1) {
        warnings.push({
          seq: null,
          line,
          code: 'INDEX_TORN_TAIL',
          message: 'final index line is an incomplete write',
        })
      } else {
        errors.push({ seq: null, line, code: 'PARSE_ERROR', message: messageOf(err) })
      }
      return
    }
    const parsed = IndexEntrySchema.safeParse(obj)
    if (!parsed.success) {
      errors.push({
        seq: null,
        line,
        code: 'SCHEMA',
        message: parsed.error.issues.map((x) => `${x.path.join('.')}: ${x.message}`).join('; '),
      })
      return
    }
    if (seen.has(parsed.data.file)) {
      errors.push({
        seq: null,
        line,
        code: 'SCHEMA',
        message: `duplicate index entry for ${parsed.data.file}`,
      })
      return
    }
    seen.add(parsed.data.file)
    entries.push(parsed.data)
  })
  return { entries, errors, warnings }
}
