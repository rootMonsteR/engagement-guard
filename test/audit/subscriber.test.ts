import { createHash } from 'node:crypto'
import { access, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { type AuditRecord, AuditRecordSchema } from '../../src/audit/record.js'
import { subscribeAudit } from '../../src/audit/subscriber.js'
import { verifyAudit } from '../../src/audit/verify.js'
import { type AuditLog, createAuditLog } from '../../src/audit/writer.js'
import type { OutputDigest } from '../../src/types.js'
import { createFakeEvents, type FakeEvents } from '../helpers/fake-events.js'

let root: string
let dir: string

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'guard-audit-sub-'))
  dir = join(root, 'audit')
})

afterEach(async () => {
  await rm(root, { recursive: true, force: true })
})

const sha256 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')
const digest = (s: string): OutputDigest => ({ sha256: sha256(s), bytes: Buffer.byteLength(s) })

/** The session the hand-emitted agent events belong to. */
const SESSION = 'sess-agent'

async function readRecords(caseId = 'no-case', sessionId = SESSION): Promise<AuditRecord[]> {
  const text = await readFile(join(dir, caseId, `${sessionId}.jsonl`), 'utf8')
  return text
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => AuditRecordSchema.parse(JSON.parse(l)))
}

const NMAP_OUT = 'Nmap scan report for 192.0.2.10\n22/tcp open ssh\n'

/** An audit log subscribed to fresh fake events, as a harness would wire them for one session. */
function startSession(opts: { caseActive: () => boolean; inspected: (id: string) => boolean }): {
  audit: AuditLog
  events: FakeEvents
} {
  const events = createFakeEvents()
  const audit = createAuditLog({ dir, sessionId: SESSION, operator: 'alice' })
  subscribeAudit(events, audit, { caseActive: opts.caseActive, inspected: opts.inspected })
  return { audit, events }
}

/** The events an unrestricted harness emits for one allowed Read call. */
function emitReadCall(events: FakeEvents): void {
  const input = { file_path: 'notes.txt' }
  events.emit({ type: 'tool.call', toolUseId: 'toolu_1', name: 'Read', input, summary: 'Read' })
  events.emit({
    type: 'permission.decision',
    toolUseId: 'toolu_1',
    decision: { kind: 'allow', reason: 'mode', source: 'mode' },
  })
  events.emit({
    type: 'tool.result',
    toolUseId: 'toolu_1',
    name: 'Read',
    isError: false,
    durationMs: 1,
    content: 'notes',
  })
}

describe('subscribeAudit with agent events emitted by hand', () => {
  it('records an inspected Bash call: tool.call, exec.spawn, exec.exit (digests), tool.result', async () => {
    const { audit, events } = startSession({
      caseActive: () => false,
      inspected: (id) => id === 'toolu_1',
    })
    const command = 'nmap -sV 192.0.2.10'
    events.emit({
      type: 'tool.call',
      toolUseId: 'toolu_1',
      name: 'Bash',
      input: { command },
      summary: command,
    })
    events.emit({
      type: 'permission.decision',
      toolUseId: 'toolu_1',
      decision: { kind: 'allow', reason: 'mode', source: 'mode' },
    })
    events.emit({
      type: 'exec.spawn',
      execId: 'exec_1',
      command,
      cwd: root,
      backend: 'fake',
      toolUseId: 'toolu_1',
    })
    events.emit({
      type: 'exec.exit',
      execId: 'exec_1',
      code: 0,
      timedOut: false,
      durationMs: 3,
      toolUseId: 'toolu_1',
      output: { stdout: digest(NMAP_OUT), stderr: digest('') },
    })
    events.emit({
      type: 'tool.result',
      toolUseId: 'toolu_1',
      name: 'Bash',
      isError: false,
      durationMs: 4,
      content: NMAP_OUT,
    })
    await audit.flush()
    const recs = await readRecords()
    expect(recs.map((r) => r.kind)).toEqual([
      'tool.call',
      'permission',
      'exec.spawn',
      'exec.exit',
      'tool.result',
    ])
    expect(new Set(recs.map((r) => r.callId))).toEqual(new Set(['toolu_1']))
    const [call, perm, spawn, exit, result] = recs as [
      AuditRecord,
      AuditRecord,
      AuditRecord,
      AuditRecord,
      AuditRecord,
    ]
    expect(call).toMatchObject({ tool: 'Bash', command: 'nmap -sV 192.0.2.10' })
    expect(perm.permission).toEqual({ kind: 'allow', source: 'mode', reason: expect.any(String) })
    expect(spawn).toMatchObject({
      command: 'nmap -sV 192.0.2.10',
      exec: { backend: 'fake', exitCode: null, stdout: null, stderr: null },
    })
    expect(exit.exec).toMatchObject({
      backend: 'fake',
      exitCode: 0,
      timedOut: false,
      stdout: { sha256: sha256(NMAP_OUT), bytes: Buffer.byteLength(NMAP_OUT) },
      stderr: { sha256: sha256(''), bytes: 0 },
    })
    expect(result.tool).toBe('Bash')
    expect(result.data).toMatchObject({
      isError: false,
      durationMs: expect.any(Number),
      contentSha256: expect.stringMatching(/^[0-9a-f]{64}$/),
      contentBytes: expect.any(Number),
    })
    const raw = await readFile(join(dir, 'no-case', `${SESSION}.jsonl`), 'utf8')
    expect(raw).not.toContain('22/tcp open ssh') // never the content, only its digest
    expect((await verifyAudit(dir)).ok).toBe(true)
  })

  it('writes nothing for an uninspected Read call with no active case', async () => {
    const { audit, events } = startSession({ caseActive: () => false, inspected: () => false })
    emitReadCall(events)
    await audit.flush()
    await expect(access(dir)).rejects.toThrow()
  })

  it('records every call and the session lifecycle while a case is active', async () => {
    const { audit, events } = startSession({ caseActive: () => true, inspected: () => false })
    events.emit({ type: 'session.start', sessionId: SESSION, cwd: root, model: 'fake' })
    audit.setCase('acme-2026')
    emitReadCall(events)
    events.emit({ type: 'turn.end', turnId: 'turn-1', stopReason: 'end_turn', steps: 2 })
    events.emit({ type: 'session.end', sessionId: SESSION })
    await audit.flush()
    const kinds = (await readRecords('no-case')).map((r) => r.kind)
    expect(kinds).toEqual(['session.start'])
    const caseKinds = (await readRecords('acme-2026')).map((r) => r.kind)
    expect(caseKinds).toEqual(['tool.call', 'permission', 'tool.result', 'session.end'])
  })
})

describe('subscribeAudit on a bare bus', () => {
  it('records a tool.call that is inspected only after it was announced, before its decision', async () => {
    const events = createFakeEvents()
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    const inspected = new Set<string>()
    subscribeAudit(events, audit, { caseActive: () => false, inspected: (id) => inspected.has(id) })
    events.emit({
      type: 'tool.call',
      toolUseId: 't1',
      name: 'Bash',
      input: { command: 'nmap 192.0.2.1' },
      summary: 'nmap',
    })
    inspected.add('t1') // the guard marks the call while the permission engine evaluates it
    events.emit({
      type: 'permission.decision',
      toolUseId: 't1',
      decision: { kind: 'deny', source: 'plugin', reason: 'out of scope' },
    })
    events.emit({
      type: 'tool.result',
      toolUseId: 't1',
      name: 'Bash',
      isError: true,
      durationMs: 0,
      content: 'denied',
    })
    await audit.flush()
    const recs = await readRecords('no-case', 's-1')
    expect(recs.map((r) => r.kind)).toEqual(['tool.call', 'permission', 'tool.result'])
    expect(recs[0]?.command).toBe('nmap 192.0.2.1')
    expect(recs[1]?.permission).toEqual({ kind: 'deny', source: 'plugin', reason: 'out of scope' })
    expect(recs[2]?.data).toEqual({
      isError: true,
      durationMs: 0,
      contentSha256: sha256('denied'),
      contentBytes: 6,
    })
  })

  it('skips permission decisions annotated by the guard (it writes its own decision record)', async () => {
    const events = createFakeEvents()
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    subscribeAudit(events, audit, { caseActive: () => true, inspected: () => true })
    events.emit({
      type: 'permission.decision',
      toolUseId: 't1',
      decision: {
        kind: 'deny',
        source: 'plugin',
        reason: 'x',
        annotations: { guard: { reason: 'OUT_OF_SCOPE' } },
      },
    })
    events.emit({
      type: 'permission.decision',
      toolUseId: 't1',
      decision: { kind: 'ask', source: 'rule', prompt: { title: 'Run nmap?' } },
    })
    await audit.flush()
    const recs = await readRecords('no-case', 's-1')
    expect(recs.map((r) => r.permission)).toEqual([
      { kind: 'ask', source: 'rule', reason: 'Run nmap?' },
    ])
  })

  it('records exec without a tool call only while a case is active', async () => {
    const events = createFakeEvents()
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    let active = false
    subscribeAudit(events, audit, { caseActive: () => active, inspected: () => true })
    events.emit({ type: 'exec.spawn', execId: 'e1', command: 'id', cwd: '/w', backend: 'local' })
    events.emit({ type: 'exec.exit', execId: 'e1', code: 0, timedOut: false, durationMs: 1 })
    active = true
    events.emit({
      type: 'exec.spawn',
      execId: 'e2',
      command: 'curl -u a:Secr3tPw https://acme.example',
      cwd: '/w',
      backend: 'local',
    })
    events.emit({ type: 'exec.exit', execId: 'e2', code: 7, timedOut: true, durationMs: 5 })
    await audit.flush()
    const recs = await readRecords('no-case', 's-1')
    expect(recs.map((r) => r.kind)).toEqual(['exec.spawn', 'exec.exit'])
    expect(recs[0]?.command).not.toContain('Secr3tPw')
    expect(recs[1]?.exec).toMatchObject({
      backend: 'local',
      exitCode: 7,
      timedOut: true,
      stdout: null,
    })
  })

  it('a failed write never throws into the bus: one onFailure call and an audit.degraded attempt', async () => {
    const events = createFakeEvents()
    const failures: string[] = []
    const attempts: string[] = []
    const failing: AuditLog = {
      caseId: 'no-case',
      degraded: true,
      setCase() {},
      async append(rec) {
        attempts.push(rec.kind)
        throw new Error('EIO: disk gone')
      },
      async flush() {},
    }
    subscribeAudit(events, failing, {
      caseActive: () => true,
      inspected: () => true,
      onFailure: (message) => failures.push(message),
    })
    expect(() =>
      events.emit({ type: 'tool.call', toolUseId: 't1', name: 'Read', input: {}, summary: 'Read' }),
    ).not.toThrow()
    await new Promise((r) => setTimeout(r, 10))
    expect(attempts).toEqual(['tool.call', 'audit.degraded'])
    expect(failures).toHaveLength(1)
    expect(failures[0]).toContain('tool.call')
    expect(failures[0]).toContain('EIO: disk gone')
  })

  it('a throwing onFailure is swallowed and the subscription keeps working', async () => {
    const events = createFakeEvents()
    const attempts: string[] = []
    const failing: AuditLog = {
      caseId: 'no-case',
      degraded: true,
      setCase() {},
      async append(rec) {
        attempts.push(rec.kind)
        throw new Error('EIO: disk gone')
      },
      async flush() {},
    }
    let calls = 0
    subscribeAudit(events, failing, {
      caseActive: () => true,
      inspected: () => true,
      onFailure: () => {
        calls++
        throw new Error('callback exploded')
      },
    })
    expect(() =>
      events.emit({ type: 'tool.call', toolUseId: 't1', name: 'Read', input: {}, summary: 'Read' }),
    ).not.toThrow()
    await new Promise((r) => setTimeout(r, 10))
    expect(calls).toBe(1)
    expect(attempts).toEqual(['tool.call', 'audit.degraded'])
    events.emit({ type: 'tool.call', toolUseId: 't2', name: 'Read', input: {}, summary: 'Read' })
    await new Promise((r) => setTimeout(r, 10))
    expect(attempts).toEqual(['tool.call', 'audit.degraded', 'tool.call'])
  })

  it('a throwing predicate is treated as "record" and never escapes', async () => {
    const events = createFakeEvents()
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    subscribeAudit(events, audit, {
      caseActive: () => {
        throw new Error('boom')
      },
      inspected: () => false,
    })
    events.emit({ type: 'tool.call', toolUseId: 't1', name: 'Read', input: {}, summary: 'Read' })
    await audit.flush()
    expect((await readRecords('no-case', 's-1')).map((r) => r.kind)).toEqual(['tool.call'])
  })

  it('unsubscribes', async () => {
    const events = createFakeEvents()
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    const off = subscribeAudit(events, audit, { caseActive: () => true, inspected: () => true })
    off()
    events.emit({ type: 'session.end', sessionId: 's-1' })
    await audit.flush()
    await expect(access(dir)).rejects.toThrow()
  })
})

describe('subscribeAudit bookkeeping (fix round 1)', () => {
  it('drops a held tool.call at turn.end, so a cancelled call is not written later', async () => {
    const events = createFakeEvents()
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    const inspected = new Set<string>()
    subscribeAudit(events, audit, { caseActive: () => false, inspected: (id) => inspected.has(id) })
    events.emit({
      type: 'tool.call',
      toolUseId: 't1',
      name: 'Bash',
      input: { command: 'id' },
      summary: 'id',
    })
    events.emit({
      type: 'turn.end',
      turnId: 'turn-1',
      stopReason: 'cancelled',
      steps: 1,
    })
    inspected.add('t1')
    events.emit({
      type: 'tool.result',
      toolUseId: 't1',
      name: 'Bash',
      isError: true,
      durationMs: 0,
      content: 'x',
    })
    await audit.flush()
    expect((await readRecords('no-case', 's-1')).map((r) => r.kind)).toEqual(['tool.result'])
  })

  it('forgets running execs at session.end', async () => {
    const events = createFakeEvents()
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    subscribeAudit(events, audit, { caseActive: () => true, inspected: () => true })
    events.emit({ type: 'exec.spawn', execId: 'e1', command: 'id', cwd: '/w', backend: 'local' })
    events.emit({ type: 'session.end', sessionId: 's-1' })
    events.emit({ type: 'exec.exit', execId: 'e1', code: 0, timedOut: false, durationMs: 1 })
    await audit.flush()
    const recs = await readRecords('no-case', 's-1')
    expect(recs.map((r) => r.kind)).toEqual(['exec.spawn', 'session.end', 'exec.exit'])
    expect(recs[2]?.exec?.backend).toBe('unknown')
  })

  it('on a permanently failing disk: one onFailure call and one audit.degraded attempt in total', async () => {
    const events = createFakeEvents()
    const seen: string[] = []
    const attempts: string[] = []
    const failing: AuditLog = {
      caseId: 'no-case',
      degraded: true,
      setCase() {},
      async append(rec) {
        attempts.push(rec.kind)
        throw new Error('EIO: disk gone')
      },
      async flush() {},
    }
    subscribeAudit(events, failing, {
      caseActive: () => true,
      inspected: () => true,
      onFailure: (message) => seen.push(message),
    })
    for (const id of ['t1', 't2', 't3']) {
      events.emit({ type: 'tool.call', toolUseId: id, name: 'Read', input: {}, summary: 'Read' })
      await new Promise((r) => setTimeout(r, 5))
    }
    expect(attempts).toEqual(['tool.call', 'audit.degraded', 'tool.call', 'tool.call'])
    expect(seen).toHaveLength(1)
  })
})
