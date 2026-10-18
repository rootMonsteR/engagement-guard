import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { type AuditRecord, AuditRecordSchema } from '../src/audit/record.js'
import { verifyAudit } from '../src/audit/verify.js'
import { recordFirstRunAck } from '../src/first-run.js'
import { createGuard, type Guard } from '../src/guard.js'
import { type ActiveCase, activeCase, TABLE_CASE_ID } from './helpers/case-fixture.js'
import { createFakeEvents } from './helpers/fake-events.js'
import { createFakeHost } from './helpers/fake-host.js'
import { bashRequest, FIXTURES, fakeLookup, IN_WINDOW } from './policy/guard-helpers.js'

const SESSION = 'sess-facade'

/** When set, `createScopeGuard` throws: a construction step after the case store fails. */
const failScopeGuard = vi.hoisted(() => ({ on: false }))

vi.mock('../src/policy/guard.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../src/policy/guard.js')>()
  return {
    ...actual,
    createScopeGuard: (ctx: Parameters<typeof actual.createScopeGuard>[0]) => {
      if (failScopeGuard.on) throw new Error('scope guard construction failed')
      return actual.createScopeGuard(ctx)
    },
  }
})

async function chainRecords(cwd: string, caseId: string): Promise<AuditRecord[]> {
  const text = await readFile(join(cwd, '.guard', 'audit', caseId, `${SESSION}.jsonl`), 'utf8')
  return text
    .split('\n')
    .filter((l) => l !== '')
    .map((l) => AuditRecordSchema.parse(JSON.parse(l)))
}

async function chainKinds(cwd: string, caseId: string): Promise<string[]> {
  return (await chainRecords(cwd, caseId)).map((r) => r.kind)
}

describe('createGuard over an active case', () => {
  let c: ActiveCase
  let g: Guard

  beforeEach(async () => {
    c = await activeCase()
    g = await createGuard({
      cwd: c.cwd,
      home: c.home,
      now: c.now,
      lookup: c.lookup,
      sessionId: SESSION,
      env: {},
      operator: 'alice',
    })
  })

  afterEach(async () => {
    await g.dispose()
    await c.cleanup()
  })

  it('passes an in-scope scan', async () => {
    expect(await g.check('nmap 192.0.2.10')).toMatchObject({ verdict: 'pass', reason: 'IN_SCOPE' })
  })

  it('denies an out-of-scope scan and names the hint', async () => {
    const o = await g.check('nmap 203.0.113.5')
    expect(o).toMatchObject({ verdict: 'deny', reason: 'OUT_OF_SCOPE' })
    if (o === 'not-inspected') throw new Error('unreachable')
    expect(o.message).toContain('engagement-guard engagement edit')
    expect(o.annotation.targets.map((t) => t.raw)).toContain('203.0.113.5')
  })

  it('passes a local command with an active case', async () => {
    expect(await g.check('ls')).toMatchObject({ verdict: 'pass', reason: 'NOT_NETWORK' })
  })

  it('audits every decision', async () => {
    await g.check('nmap 203.0.113.5')
    await g.audit.flush()
    expect((await verifyAudit(join(c.cwd, '.guard', 'audit'))).ok).toBe(true)
    expect(await chainKinds(c.cwd, TABLE_CASE_ID)).toContain('decision')
  })

  it('installs as middleware and dispose removes it', async () => {
    const host = createFakeHost({ mode: 'unrestricted' })
    g.install(host)
    expect((await host.evaluate(bashRequest('nmap 203.0.113.5', { cwd: c.cwd }))).kind).toBe('deny')
    await g.dispose()
    expect((await host.evaluate(bashRequest('nmap 203.0.113.5', { cwd: c.cwd }))).kind).toBe(
      'allow',
    )
  })

  it('subscribes to exec events of inspected calls', async () => {
    const ev = createFakeEvents()
    g.subscribe(ev)
    await g.check('nmap 192.0.2.10', { toolUseId: 'toolu_f1' })
    ev.emit({
      type: 'exec.spawn',
      execId: 'e1',
      command: 'nmap 192.0.2.10',
      cwd: c.cwd,
      backend: 'local',
      toolUseId: 'toolu_f1',
    })
    ev.emit({
      type: 'exec.exit',
      execId: 'e1',
      code: 0,
      timedOut: false,
      durationMs: 5,
      toolUseId: 'toolu_f1',
    })
    await g.audit.flush()
    const kinds = await chainKinds(c.cwd, TABLE_CASE_ID)
    expect(kinds).toContain('exec.spawn')
    expect(kinds).toContain('exec.exit')
  })

  it('records the permission after a guard pass or ask as delegated to the caller (I5)', async () => {
    expect(await g.check('nmap 192.0.2.10')).toMatchObject({ verdict: 'pass' })
    expect(await g.check('nmap 192.0.2.120-140')).toMatchObject({ verdict: 'ask' })
    await g.audit.flush()
    const records = await chainRecords(c.cwd, TABLE_CASE_ID)
    expect(records.filter((r) => r.permission?.reason === 'no host rules')).toEqual([])
    const permissions = records.filter((r) => r.kind === 'permission')
    expect(permissions).toHaveLength(2)
    for (const r of permissions) {
      expect(r.permission).toMatchObject({
        kind: 'ask',
        reason: 'decision delegated to the caller',
      })
    }
  })

  it('check and checkRequest reject after dispose (M10)', async () => {
    await g.dispose()
    await expect(g.check('nmap 203.0.113.5')).rejects.toThrow('guard disposed')
    await expect(g.checkRequest(bashRequest('nmap 203.0.113.5', { cwd: c.cwd }))).rejects.toThrow(
      'guard disposed',
    )
  })

  it('denies SCOPE_TAMPERED after the frozen file is edited and reloaded', async () => {
    const file = join(c.cwd, '.guard', 'engagement.yaml')
    const text = await readFile(file, 'utf8')
    await writeFile(
      file,
      text.replace('    - 192.0.2.0/25\n', '    - 192.0.2.0/25\n    - 192.0.2.128/25\n'),
    )
    const r = await g.engagement(['load'])
    expect(r.output).toContain('tampered')
    expect(await g.check('nmap 192.0.2.10')).toMatchObject({
      verdict: 'deny',
      reason: 'SCOPE_TAMPERED',
    })
  })
})

describe('createGuard with no case', () => {
  let cwd: string
  let home: string

  beforeEach(async () => {
    cwd = await mkdtemp(join(tmpdir(), 'guard-nocase-'))
    home = await mkdtemp(join(tmpdir(), 'guard-nocase-home-'))
  })

  afterEach(async () => {
    await rm(cwd, { recursive: true, force: true })
    await rm(home, { recursive: true, force: true })
  })

  it('rejects a workspace directory that does not exist', async () => {
    await expect(
      createGuard({ cwd: join(cwd, 'missing'), home, now: () => IN_WINDOW, env: {} }),
    ).rejects.toThrow('workspace is not a directory')
  })

  it('denies FIRST_RUN_REQUIRED with a fresh home, and still passes git clone', async () => {
    const g = await createGuard({ cwd, home, now: () => IN_WINDOW, lookup: fakeLookup, env: {} })
    expect(await g.check('nmap 192.0.2.10')).toMatchObject({
      verdict: 'deny',
      reason: 'FIRST_RUN_REQUIRED',
    })
    expect(await g.check('git clone https://github.com/x/y')).toMatchObject({
      verdict: 'pass',
      reason: 'TRUSTED_INFRA',
    })
    await g.dispose()
    expect((await verifyAudit(join(cwd, '.guard', 'audit'))).ok).toBe(true)
  })

  it('denies NO_ACTIVE_CASE once acknowledged, and still passes git clone', async () => {
    await recordFirstRunAck(home, 'alice', IN_WINDOW)
    const g = await createGuard({ cwd, home, now: () => IN_WINDOW, lookup: fakeLookup, env: {} })
    expect(await g.check('nmap 192.0.2.10')).toMatchObject({
      verdict: 'deny',
      reason: 'NO_ACTIVE_CASE',
    })
    expect(await g.check('git clone https://github.com/x/y')).toMatchObject({
      verdict: 'pass',
      reason: 'TRUSTED_INFRA',
    })
    await g.dispose()
  })
})

describe('createGuard construction failure (M10)', () => {
  let c: ActiveCase

  beforeEach(async () => {
    c = await activeCase()
  })

  afterEach(async () => {
    failScopeGuard.on = false
    await c.cleanup()
  })

  it('a step after the case store fails: the error is thrown and the audit log is flushed', async () => {
    failScopeGuard.on = true
    await expect(
      createGuard({
        cwd: c.cwd,
        home: c.home,
        now: c.now,
        lookup: c.lookup,
        sessionId: SESSION,
        env: {},
        operator: 'alice',
      }),
    ).rejects.toThrow('scope guard construction failed')
    expect(await chainKinds(c.cwd, TABLE_CASE_ID)).toContain('case.activate')
    expect((await verifyAudit(join(c.cwd, '.guard', 'audit'))).ok).toBe(true)
  })
})

describe('createGuard with a custom dirName and commandHint', () => {
  let cwd: string
  let home: string

  beforeEach(async () => {
    cwd = await mkdtemp(join(tmpdir(), 'guard-paths-'))
    home = await mkdtemp(join(tmpdir(), 'guard-paths-home-'))
    await recordFirstRunAck(home, 'alice', IN_WINDOW)
  })

  afterEach(async () => {
    await rm(cwd, { recursive: true, force: true })
    await rm(home, { recursive: true, force: true })
  })

  const custom = () =>
    createGuard({
      cwd,
      home,
      dirName: '.case',
      commandHint: 'my-tool edit',
      now: () => IN_WINDOW,
      lookup: fakeLookup,
      sessionId: SESSION,
      env: {},
      operator: 'alice',
    })

  it('engagement show names <dirName>/engagement.yaml', async () => {
    const g = await custom()
    try {
      const r = await g.engagement(['show'])
      expect(r.output).toContain('.case/engagement.yaml')
      expect(r.output).not.toContain('.guard/')
      const help = await g.engagement(['--help'])
      expect(help.output).toContain('.case/engagement.yaml')
      expect(help.output).not.toContain('.guard/')
    } finally {
      await g.dispose()
    }
  })

  it('a tampered case names the custom command hint', async () => {
    const file = join(cwd, '.case', 'engagement.yaml')
    await mkdir(join(cwd, '.case'), { recursive: true })
    await copyFile(join(FIXTURES, 'engagements', 'table-case.yaml'), file)
    const g = await custom()
    try {
      expect((await g.engagement(['freeze', '--attest', TABLE_CASE_ID])).exitCode).toBe(0)
      const text = await readFile(file, 'utf8')
      await writeFile(
        file,
        text.replace('    - 192.0.2.0/25\n', '    - 192.0.2.0/25\n    - 192.0.2.128/25\n'),
      )
      const load = await g.engagement(['load'])
      expect(load.output).toContain('tampered')
      expect(load.output).toContain('my-tool edit')
      expect(load.output).not.toContain('engagement-guard engagement edit')
      const freeze = await g.engagement(['freeze', '--attest', TABLE_CASE_ID])
      expect(freeze.exitCode).toBe(1)
      expect(freeze.output).toContain('my-tool edit')
      expect(freeze.output).not.toContain('engagement-guard engagement edit')
    } finally {
      await g.dispose()
    }
  })
})
