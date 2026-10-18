import { appendFile, mkdir, mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import type { AuditRecord } from '../../src/audit/record.js'
import { verifyAudit } from '../../src/audit/verify.js'
import { createAuditLog } from '../../src/audit/writer.js'

let dir: string
let file: string
let records: AuditRecord[]

/** A case log with records 0..2, each with a distinct command. */
beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'guard-audit-verify-'))
  const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
  audit.setCase('acme-2026')
  records = []
  for (const host of ['192.0.2.10', '192.0.2.11', '192.0.2.12']) {
    records.push(await audit.append({ kind: 'decision', command: `nmap -sV ${host}` }))
  }
  file = join(dir, 'acme-2026', 's-1.jsonl')
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

async function fileLines(): Promise<string[]> {
  return (await readFile(file, 'utf8')).split('\n').filter((l) => l !== '')
}

async function writeLines(ls: string[]): Promise<void> {
  await writeFile(file, ls.map((l) => `${l}\n`).join(''))
}

const errorsOf = async (opts?: { caseId?: string }) => {
  const report = await verifyAudit(dir, opts)
  return {
    report,
    errors: report.files.flatMap((f) => f.errors.map((e) => ({ ...e, path: f.path }))),
  }
}

describe('verifyAudit', () => {
  it('reports an intact log as ok with record count and head', async () => {
    const report = await verifyAudit(dir)
    expect(report.ok).toBe(true)
    expect(report.files).toEqual([
      {
        path: 'acme-2026/s-1.jsonl',
        caseId: 'acme-2026',
        sessionId: 's-1',
        records: 3,
        head: records[2]?.hash,
        errors: [],
      },
    ])
  })

  it('flip one byte inside record 1 → HASH_MISMATCH at seq 1 only', async () => {
    const ls = await fileLines()
    const line = ls[1] as string
    const at = line.indexOf('192.0.2.11')
    expect(at).toBeGreaterThan(0)
    ls[1] = `${line.slice(0, at + 9)}9${line.slice(at + 10)}` // …0.2.11 → …0.2.19
    await writeLines(ls)
    const { report, errors } = await errorsOf()
    expect(report.ok).toBe(false)
    expect(errors.map(({ code, seq, line }) => ({ code, seq, line }))).toEqual([
      { code: 'HASH_MISMATCH', seq: 1, line: 2 },
    ])
  })

  it('delete record 1 → SEQ_GAP and PREV_MISMATCH at seq 2', async () => {
    const ls = await fileLines()
    await writeLines([ls[0] as string, ls[2] as string])
    const { errors } = await errorsOf()
    expect(errors.map(({ code, seq }) => ({ code, seq }))).toEqual([
      { code: 'SEQ_GAP', seq: 2 },
      { code: 'PREV_MISMATCH', seq: 2 },
    ])
  })

  it('swap records 1 and 2 → SEQ_GAP', async () => {
    const ls = await fileLines()
    await writeLines([ls[0] as string, ls[2] as string, ls[1] as string])
    const { errors } = await errorsOf()
    expect(errors.filter((e) => e.code === 'SEQ_GAP').map((e) => e.seq)).toEqual([2, 1])
    expect(errors.every((e) => e.code === 'SEQ_GAP' || e.code === 'PREV_MISMATCH')).toBe(true)
  })

  it('cut the final line mid-JSON → TRUNCATED_TAIL', async () => {
    const text = await readFile(file, 'utf8')
    await writeFile(file, text.slice(0, text.length - 40))
    const { report, errors } = await errorsOf()
    expect(errors.map(({ code, line }) => ({ code, line }))).toEqual([
      { code: 'TRUNCATED_TAIL', line: 3 },
    ])
    expect(report.files[0]?.records).toBe(2)
    expect(report.files[0]?.head).toBe(records[1]?.hash)
  })

  it('a complete final record without its newline → TRUNCATED_TAIL but still counted', async () => {
    const text = await readFile(file, 'utf8')
    await writeFile(file, text.slice(0, -1))
    const { report, errors } = await errorsOf()
    expect(errors.map(({ code, seq }) => ({ code, seq }))).toEqual([
      { code: 'TRUNCATED_TAIL', seq: 2 },
    ])
    expect(report.files[0]?.records).toBe(3)
  })

  it('delete a file named in the index → MISSING_FILE', async () => {
    await unlink(file)
    const { errors } = await errorsOf()
    expect(errors.map(({ code, path, seq }) => ({ code, path, seq }))).toEqual([
      { code: 'MISSING_FILE', path: 'acme-2026/s-1.jsonl', seq: null },
    ])
  })

  it('add a stray .jsonl → UNINDEXED_FILE', async () => {
    await writeFile(join(dir, 'acme-2026', 'stray.jsonl'), '')
    const { report, errors } = await errorsOf()
    expect(report.ok).toBe(false)
    expect(errors.map(({ code, path }) => ({ code, path }))).toEqual([
      { code: 'UNINDEXED_FILE', path: 'acme-2026/stray.jsonl' },
    ])
  })

  it('a garbage line in the middle → PARSE_ERROR; valid JSON of the wrong shape → SCHEMA', async () => {
    const ls = await fileLines()
    await writeLines([
      ls[0] as string,
      'not json',
      ls[1] as string,
      '{"v":1,"seq":2}',
      ls[2] as string,
    ])
    const { errors } = await errorsOf()
    expect(errors.find((e) => e.code === 'PARSE_ERROR')).toMatchObject({ line: 2, seq: null })
    expect(errors.find((e) => e.code === 'SCHEMA')).toMatchObject({ line: 4, seq: 2 })
  })

  it('a record moved to another case chain fails at the genesis link', async () => {
    const audit = createAuditLog({ dir, sessionId: 's-2', operator: 'alice' })
    audit.setCase('other-case')
    await audit.append({ kind: 'decision' })
    const ls = await fileLines()
    await writeFile(join(dir, 'other-case', 's-2.jsonl'), `${ls[0]}\n`)
    const { errors } = await errorsOf({ caseId: 'other-case' })
    expect(errors.map((e) => e.code)).toContain('PREV_MISMATCH')
  })

  it('filters by caseId', async () => {
    const audit = createAuditLog({ dir, sessionId: 's-2', operator: 'alice' })
    await audit.append({ kind: 'session.start' })
    expect((await verifyAudit(dir)).files.map((f) => f.path).sort()).toEqual([
      'acme-2026/s-1.jsonl',
      'no-case/s-2.jsonl',
    ])
    expect((await verifyAudit(dir, { caseId: 'no-case' })).files.map((f) => f.path)).toEqual([
      'no-case/s-2.jsonl',
    ])
  })

  it('an empty or absent audit directory verifies with no files', async () => {
    const empty = join(dir, 'nothing-here')
    expect(await verifyAudit(empty)).toEqual({ ok: true, files: [] })
    await mkdir(empty)
    expect(await verifyAudit(empty)).toEqual({ ok: true, files: [] })
  })

  it('never throws on a malformed index', async () => {
    await appendFile(join(dir, 'index.jsonl'), 'garbage\n{"caseId":"x"}\n')
    await appendFile(
      join(dir, 'index.jsonl'),
      `${JSON.stringify({ caseId: 'acme-2026', sessionId: 's-1', file: '../../etc/passwd', createdAt: 'x' })}\n`,
    )
    const report = await verifyAudit(dir)
    expect(report.ok).toBe(false)
    const indexErrors = report.files.find((f) => f.path === 'index.jsonl')?.errors ?? []
    expect(indexErrors.map((e) => e.code)).toEqual(['PARSE_ERROR', 'SCHEMA', 'SCHEMA'])
    expect(report.files.find((f) => f.path === 'acme-2026/s-1.jsonl')?.errors).toEqual([])
  })

  it('reports an unreadable index path instead of throwing', async () => {
    await rm(join(dir, 'index.jsonl'))
    await mkdir(join(dir, 'index.jsonl'))
    const report = await verifyAudit(dir)
    expect(report.ok).toBe(false)
  })
})

describe('torn index tail (fix round 1, ruling P14)', () => {
  it('an unterminated, unparseable final index line is a warning that keeps ok', async () => {
    await appendFile(join(dir, 'index.jsonl'), '{"caseId":"acme-2026","sess')
    const report = await verifyAudit(dir)
    expect(report.ok).toBe(true)
    const index = report.files.find((f) => f.path === 'index.jsonl')
    expect(index?.errors).toEqual([])
    expect(index?.warnings?.map((w) => w.code)).toEqual(['INDEX_TORN_TAIL'])
  })

  it('a torn line in the middle of the index stays a PARSE_ERROR', async () => {
    const index = join(dir, 'index.jsonl')
    const text = await readFile(index, 'utf8')
    await writeFile(index, `{"caseId":"acme-2026","sess\n${text}`)
    const report = await verifyAudit(dir)
    expect(report.ok).toBe(false)
    expect(report.files.find((f) => f.path === 'index.jsonl')?.errors.map((e) => e.code)).toEqual([
      'PARSE_ERROR',
    ])
  })
})
