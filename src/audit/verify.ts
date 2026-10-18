import { readdir, readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { verifyChain } from './chain.js'
import { INDEX_FILE, type IndexEntry, parseIndex, type VerifyError } from './layout.js'
import { isNotFound, messageOf } from './util.js'

export type { VerifyError, VerifyErrorCode } from './layout.js'

export interface VerifyFileReport {
  /** Relative to the audit directory, `/`-separated (`<caseId>/<sessionId>.jsonl`). */
  path: string
  caseId: string
  sessionId: string
  /** Schema-valid records read. */
  records: number
  /** `hash` of the last schema-valid record. */
  head: string | null
  errors: VerifyError[]
  /** Findings that do not clear `ok` (a torn index tail, `INDEX_TORN_TAIL`). */
  warnings?: VerifyError[]
}

export interface VerifyReport {
  /** True when no file has an error (warnings do not count). */
  ok: boolean
  files: VerifyFileReport[]
}

/** Where verification reads an audit tree from: a directory, or a bundle in memory. */
export interface AuditSource {
  /** `index.jsonl` text, or null when absent. */
  readIndex(): Promise<string | null>
  /** A chain file's bytes by its index path, or null when absent. */
  read(file: string): Promise<Uint8Array | null>
  /** Every `.jsonl` file other than the index, by index path (`<caseId>/<name>.jsonl`). */
  listJsonl(caseId?: string): Promise<string[]>
}

export function directorySource(dir: string): AuditSource {
  const readOrNull = async (path: string): Promise<Buffer | null> => {
    try {
      return await readFile(path)
    } catch (err) {
      if (isNotFound(err)) return null
      throw err
    }
  }
  const dirEntries = async (path: string) => {
    try {
      return await readdir(path, { withFileTypes: true })
    } catch (err) {
      if (isNotFound(err)) return []
      throw err
    }
  }
  return {
    async readIndex() {
      const buf = await readOrNull(join(dir, INDEX_FILE))
      return buf === null ? null : buf.toString('utf8')
    },
    read: (file) => readOrNull(join(dir, ...file.split('/'))),
    async listJsonl(caseId) {
      const out: string[] = []
      for (const top of await dirEntries(dir)) {
        if (top.isFile() && top.name.endsWith('.jsonl') && top.name !== INDEX_FILE) {
          if (caseId === undefined) out.push(top.name)
        } else if (top.isDirectory() && (caseId === undefined || top.name === caseId)) {
          for (const f of await dirEntries(join(dir, top.name))) {
            if (f.isFile() && f.name.endsWith('.jsonl')) out.push(`${top.name}/${f.name}`)
          }
        }
      }
      return out.sort()
    },
  }
}

const fileError = (code: VerifyError['code'], message: string): VerifyError => ({
  seq: null,
  line: 0,
  code,
  message,
})

/**
 * Verifies the audit tree a source exposes: the index first, then each indexed chain (filtered by
 * `caseId`), then `.jsonl` files the index does not name. Never throws. `displayPrefix` is put in
 * front of every reported path (`audit/` inside an export bundle).
 */
export async function verifySource(
  src: AuditSource,
  opts: { caseId?: string; displayPrefix?: string } = {},
): Promise<VerifyReport> {
  const prefix = opts.displayPrefix ?? ''
  const files: VerifyFileReport[] = []
  const report = (path: string, caseId: string, sessionId: string, errors: VerifyError[]) =>
    files.push({ path, caseId, sessionId, records: 0, head: null, errors })
  try {
    let entries: IndexEntry[] = []
    let indexText: string | null = null
    try {
      indexText = await src.readIndex()
    } catch (err) {
      report(`${prefix}${INDEX_FILE}`, '', '', [
        fileError('PARSE_ERROR', `cannot read index: ${messageOf(err)}`),
      ])
    }
    if (indexText !== null) {
      const parsed = parseIndex(indexText)
      entries = parsed.entries
      if (parsed.errors.length > 0 || parsed.warnings.length > 0) {
        files.push({
          path: `${prefix}${INDEX_FILE}`,
          caseId: '',
          sessionId: '',
          records: 0,
          head: null,
          errors: parsed.errors,
          ...(parsed.warnings.length > 0 ? { warnings: parsed.warnings } : {}),
        })
      }
    }
    const indexed = new Set(entries.map((e) => e.file))
    for (const e of entries) {
      if (opts.caseId !== undefined && e.caseId !== opts.caseId) continue
      const path = `${prefix}${e.file}`
      let bytes: Uint8Array | null
      try {
        bytes = await src.read(e.file)
      } catch (err) {
        report(path, e.caseId, e.sessionId, [
          fileError('PARSE_ERROR', `cannot read file: ${messageOf(err)}`),
        ])
        continue
      }
      if (bytes === null) {
        report(path, e.caseId, e.sessionId, [
          fileError('MISSING_FILE', 'file named in the index is missing'),
        ])
        continue
      }
      const check = verifyChain(Buffer.from(bytes).toString('utf8'), e.caseId, e.sessionId)
      files.push({
        path,
        caseId: e.caseId,
        sessionId: e.sessionId,
        records: check.records,
        head: check.head,
        errors: check.errors,
      })
    }
    let stray: string[] = []
    try {
      stray = (await src.listJsonl(opts.caseId)).filter((f) => !indexed.has(f))
    } catch (err) {
      report(prefix || '.', '', '', [
        fileError('PARSE_ERROR', `cannot list audit files: ${messageOf(err)}`),
      ])
    }
    for (const f of stray) {
      const slash = f.indexOf('/')
      report(`${prefix}${f}`, slash === -1 ? '' : f.slice(0, slash), '', [
        fileError('UNINDEXED_FILE', 'file is not named in the index'),
      ])
    }
  } catch (err) {
    report(prefix || '.', '', '', [
      fileError('PARSE_ERROR', `verification failed: ${messageOf(err)}`),
    ])
  }
  return { ok: files.every((f) => f.errors.length === 0), files }
}

/** Verifies `<dir>` (`<cwd>/.guard/audit`): index, every indexed chain, stray files. Never throws. */
export function verifyAudit(dir: string, opts: { caseId?: string } = {}): Promise<VerifyReport> {
  return verifySource(directorySource(dir), opts)
}
