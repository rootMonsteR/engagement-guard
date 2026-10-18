import { access, appendFile, mkdir, mkdtemp, open, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  type AuditRecord,
  AuditRecordSchema,
  genesisHash,
  hashRecord,
} from '../../src/audit/record.js'
import { verifyAudit } from '../../src/audit/verify.js'
import { createAuditLog } from '../../src/audit/writer.js'

let root: string
let dir: string

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'guard-audit-writer-'))
  dir = join(root, '.guard', 'audit')
})

afterEach(async () => {
  vi.restoreAllMocks()
  await rm(root, { recursive: true, force: true })
})

const fixedNow = () => new Date('2026-10-21T08:00:00.000Z')

async function lines(path: string): Promise<AuditRecord[]> {
  const text = await readFile(path, 'utf8')
  expect(text.endsWith('\n')).toBe(true)
  return text
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => AuditRecordSchema.parse(JSON.parse(l)))
}

async function indexLines(): Promise<Record<string, unknown>[]> {
  const text = await readFile(join(dir, 'index.jsonl'), 'utf8')
  return text
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => JSON.parse(l))
}

const exists = (p: string) =>
  access(p).then(
    () => true,
    () => false,
  )

/** The (non-public) FileHandle prototype, for spying on sync/appendFile. */
async function fileHandleProto(): Promise<{
  sync: () => Promise<void>
  appendFile: () => Promise<void>
}> {
  const probe = join(root, 'probe')
  const h = await open(probe, 'w')
  const proto = Object.getPrototypeOf(h)
  await h.close()
  return proto
}

describe('createAuditLog', () => {
  it('chains appends: seq 0, 1, 2 from the genesis hash, one JSON line each', async () => {
    const audit = createAuditLog({
      dir,
      sessionId: 's-1',
      operator: 'alice',
      now: fixedNow,
      mono: () => 12.5,
    })
    expect(audit.caseId).toBe('no-case')
    expect(await exists(dir)).toBe(false) // created lazily
    const a = await audit.append({ kind: 'session.start', data: { cwd: '/w' } })
    const b = await audit.append({
      kind: 'tool.call',
      callId: 'toolu_1',
      tool: 'Bash',
      command: 'id',
    })
    const c = await audit.append({ kind: 'tool.result', callId: 'toolu_1', tool: 'Bash' })
    expect([a.seq, b.seq, c.seq]).toEqual([0, 1, 2])
    expect(a.prevHash).toBe(genesisHash('no-case', 's-1'))
    expect(b.prevHash).toBe(a.hash)
    expect(c.prevHash).toBe(b.hash)
    for (const r of [a, b, c]) {
      const { hash, ...rest } = r
      expect(hashRecord(rest)).toBe(hash)
    }
    expect(a).toMatchObject({
      v: 1,
      ts: '2026-10-21T08:00:00.000Z',
      mono: 12.5,
      operator: 'alice',
      caseId: 'no-case',
      sessionId: 's-1',
      callId: null,
      parentCallId: null,
      tool: null,
      command: null,
      targets: [],
      scope: null,
      permission: null,
      exec: null,
    })
    expect(await lines(join(dir, 'no-case', 's-1.jsonl'))).toEqual([a, b, c])
    expect(await indexLines()).toEqual([
      {
        caseId: 'no-case',
        sessionId: 's-1',
        file: 'no-case/s-1.jsonl',
        createdAt: '2026-10-21T08:00:00.000Z',
      },
    ])
  })

  it('setCase starts a new chain file at seq 0 and adds an index line', async () => {
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice', now: fixedNow })
    await audit.append({ kind: 'session.start' })
    audit.setCase('acme-2026')
    expect(audit.caseId).toBe('acme-2026')
    const r = await audit.append({ kind: 'case.activate' })
    expect(r.seq).toBe(0)
    expect(r.caseId).toBe('acme-2026')
    expect(r.prevHash).toBe(genesisHash('acme-2026', 's-1'))
    expect(await lines(join(dir, 'acme-2026', 's-1.jsonl'))).toEqual([r])
    const index = await indexLines()
    expect(index.map((l) => l.file)).toEqual(['no-case/s-1.jsonl', 'acme-2026/s-1.jsonl'])
    expect((await verifyAudit(dir)).ok).toBe(true)
  })

  it('records the case current at append() time even while earlier writes are queued', async () => {
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    const first = audit.append({ kind: 'session.start' })
    audit.setCase('acme-2026')
    const second = audit.append({ kind: 'case.activate' })
    expect((await first).caseId).toBe('no-case')
    expect((await second).caseId).toBe('acme-2026')
  })

  it('rejects an unsafe case id', () => {
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    expect(() => audit.setCase('../escape')).toThrow(/case id/i)
    expect(() => audit.setCase('')).toThrow(/case id/i)
    expect(audit.caseId).toBe('no-case')
  })

  it('serialises concurrent appends into one gap-free chain', async () => {
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    const recs = await Promise.all(
      Array.from({ length: 20 }, (_, i) => audit.append({ kind: 'tool.call', callId: `c-${i}` })),
    )
    expect(recs.map((r) => r.seq)).toEqual(Array.from({ length: 20 }, (_, i) => i))
    expect((await lines(join(dir, 'no-case', 's-1.jsonl'))).map((r) => r.callId)).toEqual(
      recs.map((r) => r.callId),
    )
    expect((await verifyAudit(dir)).ok).toBe(true)
  })

  it('two locked logs on one chain interleave into a gap-free, verifiable chain', async () => {
    const a = createAuditLog({ dir, sessionId: 's', operator: 'alice', lock: true })
    const b = createAuditLog({ dir, sessionId: 's', operator: 'alice', lock: true })
    a.setCase('c')
    b.setCase('c')
    await Promise.all(
      Array.from({ length: 20 }, (_, i) =>
        (i % 2 === 0 ? a : b).append({ kind: 'tool.call', callId: `c-${i}` }),
      ),
    )
    const recs = await lines(join(dir, 'c', 's.jsonl'))
    expect(recs.map((r) => r.seq)).toEqual(Array.from({ length: 20 }, (_, i) => i))
    expect(new Set(recs.map((r) => r.callId)).size).toBe(20)
    expect((await verifyAudit(dir)).ok).toBe(true)
    expect(a.degraded).toBe(false)
    expect(b.degraded).toBe(false)
  })

  it('writes the index under the audit-root lock, so a held root lock blocks the first append', async () => {
    const audit = createAuditLog({
      dir,
      sessionId: 's',
      operator: 'alice',
      lock: true,
      lockTimeoutMs: 200,
    })
    audit.setCase('c')
    await mkdir(join(dir, '.lock'), { recursive: true })
    const started = Date.now()
    await expect(audit.append({ kind: 'tool.call' })).rejects.toThrow('audit write failed')
    expect(Date.now() - started).toBeLessThan(3000)
    expect(audit.degraded).toBe(true)
  })

  it('two locked logs on two cases index both chains without a torn line', async () => {
    const a = createAuditLog({ dir, sessionId: 's', operator: 'alice', lock: true })
    const b = createAuditLog({ dir, sessionId: 's', operator: 'alice', lock: true })
    a.setCase('case-a')
    b.setCase('case-b')
    await Promise.all(
      Array.from({ length: 10 }, (_, i) => [
        a.append({ kind: 'tool.call', callId: `a-${i}` }),
        b.append({ kind: 'tool.call', callId: `b-${i}` }),
      ]).flat(),
    )
    const index = await indexLines()
    expect(index.map((e) => e.caseId).sort()).toEqual(['case-a', 'case-b'])
    expect((await verifyAudit(dir)).ok).toBe(true)
  })

  it('a lock that cannot be taken rejects the append and marks the log degraded', async () => {
    const audit = createAuditLog({ dir, sessionId: 's', operator: 'alice', lock: true })
    audit.setCase('c')
    await mkdir(join(dir, 'c', '.lock'), { recursive: true })
    await expect(audit.append({ kind: 'tool.call' })).rejects.toThrow('audit write failed')
    expect(audit.degraded).toBe(true)
  }, 15_000)

  describe('a locked log refreshes from the chain tail (I4)', () => {
    const file = (name = 's.jsonl') => join(dir, 'c', name)
    const locked = () => {
      const log = createAuditLog({ dir, sessionId: 's', operator: 'alice', lock: true })
      log.setCase('c')
      return log
    }
    /** Rewrites record `seq` in the middle of the file; the tail stays a clean, parseable line. */
    async function tamperMiddle(seq: number): Promise<void> {
      const text = await readFile(file(), 'utf8')
      const out = text
        .split('\n')
        .map((l) =>
          l.includes(`"seq":${seq},`) ? l.replace('"operator":"alice"', '"operator":"mallory"') : l,
        )
        .join('\n')
      expect(out).not.toBe(text)
      await writeFile(file(), out)
    }

    it('continues the same file from the last line, without re-verifying the whole chain', async () => {
      const a = locked()
      for (let i = 0; i < 3; i++) await a.append({ kind: 'tool.call', callId: `c-${i}` })
      await tamperMiddle(1)
      const r = await a.append({ kind: 'tool.call', callId: 'c-3' })
      // A full re-open would have found the bad middle record and started s.1.jsonl at seq 0.
      expect(r.seq).toBe(3)
      expect(await exists(file('s.1.jsonl'))).toBe(false)
      expect((await lines(file())).at(-1)).toEqual(r)
    })

    it('finds the last line when it is longer than the first tail window', async () => {
      const a = locked()
      await a.append({ kind: 'tool.call' })
      await a.append({ kind: 'tool.call', data: { blob: 'x'.repeat(150_000) } })
      await tamperMiddle(0)
      const r = await a.append({ kind: 'tool.call' })
      expect(r.seq).toBe(2)
      expect(await exists(file('s.1.jsonl'))).toBe(false)
    })

    it('falls back to a full re-open (a new segment) when the last line is torn', async () => {
      const a = locked()
      await a.append({ kind: 'tool.call' })
      await a.append({ kind: 'tool.call' })
      await appendFile(file(), '{"v":1,"seq":2,"ts":"2026')
      const r = await a.append({ kind: 'tool.call' })
      expect(r.seq).toBe(0)
      expect(r.prevHash).toBe(genesisHash('c', 's'))
      expect(await lines(file('s.1.jsonl'))).toEqual([r])
      expect(a.degraded).toBe(false)
    })

    it('falls back to a full re-open when the chain file is gone', async () => {
      const a = locked()
      await a.append({ kind: 'tool.call' })
      await rm(file())
      const r = await a.append({ kind: 'tool.call' })
      expect(r.seq).toBe(0)
      expect(r.prevHash).toBe(genesisHash('c', 's'))
    })

    it('falls back when the last line is a record of another session', async () => {
      const a = locked()
      await a.append({ kind: 'tool.call' })
      const other = createAuditLog({ dir: join(root, 'other'), sessionId: 'x', operator: 'a' })
      other.setCase('c')
      const foreign = await other.append({ kind: 'tool.call' })
      await appendFile(file(), `${JSON.stringify(foreign)}\n`)
      const r = await a.append({ kind: 'tool.call' })
      expect(r.seq).toBe(0)
      expect(await lines(file('s.1.jsonl'))).toEqual([r])
    })

    it('follows a newer segment started by another process', async () => {
      const a = locked()
      for (let i = 0; i < 3; i++) await a.append({ kind: 'tool.call' })
      await tamperMiddle(1)
      // A fresh instance verifies the whole file, rejects it and starts s.1.jsonl.
      const b = locked()
      expect((await b.append({ kind: 'tool.call' })).seq).toBe(0)
      const r = await a.append({ kind: 'tool.call' })
      expect(r.seq).toBe(1)
      expect((await lines(file('s.1.jsonl'))).map((x) => x.seq)).toEqual([0, 1])
    })
  })

  it('redacts command, target raw values and data string leaves before hashing', async () => {
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    const r = await audit.append({
      kind: 'decision',
      command: 'mysql -uroot -pTopSecret -h 192.0.2.5',
      targets: [{ raw: 'mysql://root:TopSecret@192.0.2.5', class: 'in', rule: null, resolved: [] }],
      data: { args: ['--password', 'TopSecret'], password: 'TopSecret' },
    })
    const raw = await readFile(join(dir, 'no-case', 's-1.jsonl'), 'utf8')
    expect(raw).not.toContain('TopSecret')
    const { hash, ...rest } = r
    expect(hashRecord(rest)).toBe(hash)
  })

  it('redacts the permission reason and snapshots the input at append() time', async () => {
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    const permission = {
      kind: 'ask' as const,
      source: 'rule',
      reason: 'Run curl -u admin:S3cr3t! https://acme.example?',
    }
    const pending = audit.append({ kind: 'permission', permission })
    permission.source = 'mutated'
    const r = await pending
    expect(r.permission).toEqual({
      kind: 'ask',
      source: 'rule',
      reason: 'Run curl -u admin:[REDACTED] https://acme.example?',
    })
    expect(await readFile(join(dir, 'no-case', 's-1.jsonl'), 'utf8')).not.toContain('S3cr3t!')
  })

  it('rejects invalid input without marking the log degraded', async () => {
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    await expect(
      audit.append({ kind: 'tool.call', data: { when: new Date() } as Record<string, unknown> }),
    ).rejects.toThrow()
    await expect(audit.append({ kind: 'nope' } as never)).rejects.toThrow()
    expect(audit.degraded).toBe(false)
    expect((await audit.append({ kind: 'tool.call' })).seq).toBe(0)
  })

  it('fsyncs only when asked (sync: true)', async () => {
    const proto = await fileHandleProto()
    const sync = vi.spyOn(proto, 'sync')
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    await audit.append({ kind: 'tool.call' })
    const before = sync.mock.calls.length
    await audit.append({ kind: 'decision' }, { sync: true })
    expect(sync.mock.calls.length).toBeGreaterThan(before)
    const afterSync = sync.mock.calls.length
    await audit.append({ kind: 'tool.result' })
    expect(sync.mock.calls.length).toBe(afterSync)
  })

  it('a failed write rejects that append and marks the log degraded for good', async () => {
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    await audit.append({ kind: 'session.start' })
    expect(audit.degraded).toBe(false)
    const proto = await fileHandleProto()
    vi.spyOn(proto, 'appendFile').mockRejectedValueOnce(new Error('ENOSPC: no space left'))
    await expect(audit.append({ kind: 'decision' })).rejects.toThrow(/ENOSPC/)
    expect(audit.degraded).toBe(true)
    // Writing works again, the chain continues without a gap, but degraded stays set.
    const next = await audit.append({ kind: 'audit.degraded' })
    expect(next.seq).toBe(1)
    expect(audit.degraded).toBe(true)
    expect((await verifyAudit(dir)).ok).toBe(true)
  })

  it('continues an existing file whose tail verifies', async () => {
    const first = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    await first.append({ kind: 'session.start' })
    const last = await first.append({ kind: 'session.end' })
    const second = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    const r = await second.append({ kind: 'session.start' })
    expect(r.seq).toBe(2)
    expect(r.prevHash).toBe(last.hash)
    expect(await indexLines()).toHaveLength(1)
    expect((await verifyAudit(dir)).ok).toBe(true)
  })

  it('starts a new numbered segment when the existing file does not verify', async () => {
    const first = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    await first.append({ kind: 'session.start' })
    const path = join(dir, 'no-case', 's-1.jsonl')
    await appendFile(path, '{"v":1,"seq":1,"ts":"2026') // torn write
    const second = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    const r = await second.append({ kind: 'session.start' })
    expect(r.seq).toBe(0)
    expect(r.prevHash).toBe(genesisHash('no-case', 's-1'))
    expect(await lines(join(dir, 'no-case', 's-1.1.jsonl'))).toEqual([r])
    expect((await indexLines()).map((l) => l.file)).toEqual([
      'no-case/s-1.jsonl',
      'no-case/s-1.1.jsonl',
    ])
    // A third instance continues the good segment rather than the torn file.
    const third = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    expect((await third.append({ kind: 'session.end' })).seq).toBe(1)
    const report = await verifyAudit(dir)
    expect(report.files.find((f) => f.path === 'no-case/s-1.jsonl')?.errors[0]?.code).toBe(
      'TRUNCATED_TAIL',
    )
    expect(report.files.find((f) => f.path === 'no-case/s-1.1.jsonl')?.errors).toEqual([])
  })

  it('indexes an existing but unindexed empty file before continuing it', async () => {
    const path = join(dir, 'no-case', 's-1.jsonl')
    await createAuditLog({ dir, sessionId: 'other', operator: 'a' }).append({
      kind: 'session.start',
    })
    await writeFile(path, '')
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    expect((await audit.append({ kind: 'session.start' })).seq).toBe(0)
    expect((await indexLines()).map((l) => l.file)).toContain('no-case/s-1.jsonl')
    expect((await verifyAudit(dir)).ok).toBe(true)
  })

  it('flush() waits for queued appends', async () => {
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    void audit.append({ kind: 'session.start' })
    void audit.append({ kind: 'session.end' })
    await audit.flush()
    expect(await lines(join(dir, 'no-case', 's-1.jsonl'))).toHaveLength(2)
  })
})

describe('index repair (fix round 1, ruling P14)', () => {
  it('truncates a torn trailing index line before adding an entry', async () => {
    await createAuditLog({ dir, sessionId: 's-1', operator: 'alice' }).append({
      kind: 'session.start',
    })
    await appendFile(join(dir, 'index.jsonl'), '{"caseId":"no-case","sess')
    await createAuditLog({ dir, sessionId: 's-2', operator: 'alice' }).append({
      kind: 'session.start',
    })
    const text = await readFile(join(dir, 'index.jsonl'), 'utf8')
    expect(text.endsWith('\n')).toBe(true)
    for (const line of text.split('\n').filter((l) => l !== '')) {
      expect(() => JSON.parse(line), line).not.toThrow()
    }
    expect((await indexLines()).map((l) => l.file)).toEqual([
      'no-case/s-1.jsonl',
      'no-case/s-2.jsonl',
    ])
    const report = await verifyAudit(dir)
    expect(report.ok).toBe(true)
    expect(report.files.find((f) => f.path === 'index.jsonl')).toBeUndefined()
  })

  it('keeps a complete final index entry that only lacks its newline', async () => {
    await createAuditLog({ dir, sessionId: 's-1', operator: 'alice' }).append({
      kind: 'session.start',
    })
    const index = join(dir, 'index.jsonl')
    await writeFile(index, (await readFile(index, 'utf8')).slice(0, -1))
    await createAuditLog({ dir, sessionId: 's-2', operator: 'alice' }).append({
      kind: 'session.start',
    })
    expect((await indexLines()).map((l) => l.file)).toEqual([
      'no-case/s-1.jsonl',
      'no-case/s-2.jsonl',
    ])
    expect((await verifyAudit(dir)).ok).toBe(true)
  })
})
