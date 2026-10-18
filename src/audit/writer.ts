import { mkdir, open, readdir, readFile, truncate } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { canonicalJson } from '../canonical.js'
import { verifyChain } from './chain.js'
import {
  chainFile,
  INDEX_FILE,
  type IndexEntry,
  IndexEntrySchema,
  parseIndex,
  SAFE_CASE_ID,
  SAFE_SESSION_ID,
} from './layout.js'
import { withChainLock } from './lock.js'
import { type AuditRecord, AuditRecordSchema, genesisHash, hashRecord } from './record.js'
import { redact, redactDeep } from './redact.js'
import { isNotFound, messageOf } from './util.js'

/** What a caller supplies; the log fills in the rest (seq, time, operator, case, chain hashes). */
export type AuditRecordInput = Pick<AuditRecord, 'kind'> &
  Partial<
    Pick<
      AuditRecord,
      | 'callId'
      | 'parentCallId'
      | 'tool'
      | 'command'
      | 'targets'
      | 'scope'
      | 'permission'
      | 'exec'
      | 'data'
    >
  >

export interface AuditLog {
  /** `'no-case'` until `setCase`. */
  readonly caseId: string
  /** Following records go to `<dir>/<caseId>/<sessionId>.jsonl` (a new chain and index entry). */
  setCase(caseId: string): void
  /**
   * Redacts, assigns `seq`/`prevHash`, hashes and appends one JSON line (fsync when `sync`).
   * Rejects when the write fails, which also sets `degraded`.
   */
  append(rec: AuditRecordInput, opts?: { sync?: boolean }): Promise<AuditRecord>
  /** True after any failed write, for the rest of this log's life (the guard then denies). */
  readonly degraded: boolean
  /** Resolves once every append queued so far has settled. */
  flush(): Promise<void>
}

export const NO_CASE = 'no-case'

const ZERO_HASH = '0'.repeat(64)

interface Chain {
  caseId: string
  /** Index path, `<caseId>/<file>.jsonl`. */
  file: string
  /** The segment number of `file` (0 for `<sessionId>.jsonl`). */
  segment: number
  seq: number
  prevHash: string
}

/**
 * Repairs a torn final line of `index.jsonl` (ruling P14): a complete entry that only lacks its
 * `\n` gets one; an unparseable partial write is cut back to the last complete line. The index
 * is not hash-chained (every entry is self-describing), so this loses nothing verifiable.
 * Returns the repaired text.
 */
async function repairIndexTail(path: string, text: string): Promise<string> {
  if (text === '' || text.endsWith('\n')) return text
  const cut = text.lastIndexOf('\n') + 1
  const tail = text.slice(cut)
  let complete = false
  try {
    complete = IndexEntrySchema.safeParse(JSON.parse(tail)).success
  } catch {
    complete = false
  }
  if (complete) {
    await appendText(path, '\n', true)
    return `${text}\n`
  }
  const kept = text.slice(0, cut)
  await truncate(path, Buffer.byteLength(kept, 'utf8'))
  return kept
}

/** Appends `text` to `path` (created with its directory if needed); fsync when `sync`. */
async function appendText(path: string, text: string, sync: boolean): Promise<void> {
  await mkdir(dirname(path), { recursive: true })
  const fh = await open(path, 'a')
  try {
    await fh.appendFile(text, 'utf8')
    if (sync) await fh.sync()
  } finally {
    await fh.close()
  }
}

/** How much of a chain file's end is read at first to find its last line (grows if needed). */
const TAIL_WINDOW = 64 * 1024

/**
 * The last complete line of the file at `path`, read from its end: `''` for an empty file,
 * `undefined` when the file does not end with `\n` (a torn write). Rejects when it is missing.
 */
async function lastLine(path: string): Promise<string | undefined> {
  const fh = await open(path, 'r')
  try {
    const { size } = await fh.stat()
    if (size === 0) return ''
    for (let window = TAIL_WINDOW; ; window *= 4) {
      const start = Math.max(0, size - window)
      const buf = Buffer.alloc(size - start)
      await fh.read(buf, 0, buf.length, start)
      // A window that starts inside a multi-byte character only garbles text before the first
      // newline, which is never the part returned.
      const text = buf.toString('utf8')
      if (!text.endsWith('\n')) return undefined
      const body = text.slice(0, -1)
      const nl = body.lastIndexOf('\n')
      if (nl !== -1 || start === 0) return body.slice(nl + 1)
    }
  } finally {
    await fh.close()
  }
}

/**
 * The append-only, hash-chained audit log of one session (spec §6.6). Appends are serialised; the
 * directory, chain file and index entry are created lazily by the first append for a case. An
 * existing chain file (same session resumed, or after a failed write) is continued only when it
 * verifies completely; otherwise a new segment `<sessionId>.<n>.jsonl` is started and indexed.
 */
export function createAuditLog(opts: {
  /** `<cwd>/.guard/audit` (`GuardPaths.auditDir` under the workspace) */
  dir: string
  sessionId: string
  operator: string
  now?: () => Date
  /** Monotonic milliseconds; default `performance.now()`. */
  mono?: () => number
  /**
   * Take `<dir>/<caseId>/.lock` around every append and refresh the chain from its tail under it
   * (the last line of the current segment; a full re-open only when that does not hold), so several
   * processes (parallel hooks, the CLI) can append to one chain (spec §4.3). A lock timeout
   * rejects the append and marks the log degraded. Default: off (one process owns the log).
   */
  lock?: boolean
  /** How long an append waits for a lock before failing closed (default 5000 ms). */
  lockTimeoutMs?: number
}): AuditLog {
  const { dir, sessionId, operator } = opts
  const lock = opts.lock === true
  const lockOpts = opts.lockTimeoutMs === undefined ? {} : { timeoutMs: opts.lockTimeoutMs }
  if (!SAFE_SESSION_ID.test(sessionId)) throw new Error(`invalid audit session id: ${sessionId}`)
  const now = opts.now ?? (() => new Date())
  const mono = opts.mono ?? (() => performance.now())
  let caseId = NO_CASE
  let degraded = false
  let chain: Chain | undefined
  let queue: Promise<unknown> = Promise.resolve()

  const segmentPattern = new RegExp(`^${sessionId}(?:\\.([1-9][0-9]*))?\\.jsonl$`)

  /** Highest existing segment number for this session in a case directory, -1 when none. */
  async function lastSegment(forCase: string): Promise<number> {
    let names: string[]
    try {
      names = await readdir(join(dir, forCase))
    } catch (err) {
      if (isNotFound(err)) return -1
      throw err
    }
    let last = -1
    for (const name of names) {
      const m = segmentPattern.exec(name)
      if (m) last = Math.max(last, m[1] === undefined ? 0 : Number(m[1]))
    }
    return last
  }

  async function ensureIndexed(forCase: string, file: string): Promise<void> {
    const path = join(dir, INDEX_FILE)
    const indexWrite = async (): Promise<void> => {
      let text = ''
      try {
        text = await readFile(path, 'utf8')
      } catch (err) {
        if (!isNotFound(err)) throw err
      }
      text = await repairIndexTail(path, text)
      if (parseIndex(text).entries.some((e) => e.file === file)) return
      const entry: IndexEntry = { caseId: forCase, sessionId, file, createdAt: now().toISOString() }
      await appendText(path, `${JSON.stringify(entry)}\n`, true)
    }
    // The index is shared by every case, so its read-repair-append runs under the audit-root
    // lock (`<dir>/.lock`), not only the per-case one: two cases opened at once from two
    // processes would otherwise race on it.
    if (lock) await withChainLock(dir, indexWrite, lockOpts)
    else await indexWrite()
  }

  async function openChain(forCase: string): Promise<Chain> {
    const last = await lastSegment(forCase)
    let segment = Math.max(last, 0)
    let seq = 0
    let prevHash = genesisHash(forCase, sessionId)
    if (last >= 0) {
      const text = await readFile(
        join(dir, ...chainFile(forCase, sessionId, last).split('/')),
        'utf8',
      )
      const check = verifyChain(text, forCase, sessionId)
      if (check.errors.length === 0) {
        seq = check.lastSeq + 1
        prevHash = check.head ?? prevHash
      } else {
        segment = last + 1
      }
    }
    const file = chainFile(forCase, sessionId, segment)
    // Create the file before indexing it, so the index never names a file that does not exist.
    await appendText(join(dir, ...file.split('/')), '', false)
    await ensureIndexed(forCase, file)
    return { caseId: forCase, file, segment, seq, prevHash }
  }

  /**
   * Under the lock: the chain as it now stands on disk, read from the tail of the current
   * segment (its last line, which another process may have written) rather than re-verifying
   * the whole file. Falls back to `openChain` when a newer segment exists, or the file is
   * missing or empty, or its last line is torn, does not parse, does not hash, or belongs to
   * another case or session.
   */
  async function refreshChain(c: Chain): Promise<Chain> {
    if ((await lastSegment(c.caseId)) !== c.segment) return openChain(c.caseId)
    let line: string | undefined
    try {
      line = await lastLine(join(dir, ...c.file.split('/')))
    } catch (err) {
      if (isNotFound(err)) return openChain(c.caseId)
      throw err
    }
    if (line === undefined || line === '') return openChain(c.caseId)
    let rec: AuditRecord | undefined
    try {
      const parsed = AuditRecordSchema.safeParse(JSON.parse(line))
      rec = parsed.success ? parsed.data : undefined
    } catch {
      rec = undefined
    }
    if (rec === undefined || rec.caseId !== c.caseId || rec.sessionId !== sessionId) {
      return openChain(c.caseId)
    }
    const { hash, ...unhashed } = rec
    if (hashRecord(unhashed) !== hash) return openChain(c.caseId)
    return { ...c, seq: rec.seq + 1, prevHash: hash }
  }

  /** Builds and validates the record body at call time; throws on bad input (not a write failure). */
  function prepare(
    input: AuditRecordInput,
    forCase: string,
  ): Omit<AuditRecord, 'seq' | 'prevHash' | 'hash'> {
    const body = {
      v: 1 as const,
      ts: now().toISOString(),
      mono: mono(),
      operator,
      caseId: forCase,
      sessionId,
      kind: input.kind,
      callId: input.callId ?? null,
      parentCallId: input.parentCallId ?? null,
      tool: input.tool ?? null,
      command: input.command == null ? null : redact(input.command),
      targets: (input.targets ?? []).map((t) => ({ ...t, raw: redact(t.raw) })),
      scope: input.scope ?? null,
      // Free text: an ask prompt's title can echo the command.
      permission:
        input.permission == null
          ? null
          : {
              ...input.permission,
              reason: input.permission.reason == null ? null : redact(input.permission.reason),
            },
      exec: input.exec ?? null,
      data: input.data == null ? null : redactDeep(input.data),
    }
    AuditRecordSchema.parse({ ...body, seq: 0, prevHash: ZERO_HASH, hash: ZERO_HASH })
    canonicalJson(body)
    // A snapshot: later changes to the caller's objects cannot alter the queued record.
    return structuredClone(body)
  }

  return {
    get caseId() {
      return caseId
    },
    get degraded() {
      return degraded
    },
    setCase(next) {
      if (!SAFE_CASE_ID.test(next))
        throw new Error(`invalid audit case id: ${JSON.stringify(next)}`)
      caseId = next
    },
    append(input, appendOpts = {}) {
      const forCase = caseId
      let body: ReturnType<typeof prepare>
      try {
        body = prepare(input, forCase)
      } catch (err) {
        return Promise.reject(err)
      }
      const write = async (): Promise<AuditRecord> => {
        if (chain === undefined || chain.caseId !== forCase) chain = await openChain(forCase)
        // Under the lock another process may have appended: continue from the file's last line.
        else if (lock) chain = await refreshChain(chain)
        const { v, ...fields } = body
        // Key order only affects how the line reads; the hash is over canonical JSON.
        const unhashed = { v, seq: chain.seq, ...fields, prevHash: chain.prevHash }
        const record: AuditRecord = { ...unhashed, hash: hashRecord(unhashed) }
        await appendText(
          join(dir, ...chain.file.split('/')),
          `${JSON.stringify(record)}\n`,
          appendOpts.sync === true,
        )
        chain.seq = record.seq + 1
        chain.prevHash = record.hash
        return record
      }
      const task = queue.then(async (): Promise<AuditRecord> => {
        try {
          return lock ? await withChainLock(join(dir, forCase), write, lockOpts) : await write()
        } catch (err) {
          degraded = true
          // Re-open on the next append: continue only if what reached the disk still verifies.
          chain = undefined
          throw new Error(`audit write failed: ${messageOf(err)}`, { cause: err })
        }
      })
      queue = task.catch(() => {})
      return task
    },
    async flush() {
      await queue
    },
  }
}
