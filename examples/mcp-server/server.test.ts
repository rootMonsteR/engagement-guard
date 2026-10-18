import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { createGuard, type Guard, verifyAudit } from 'engagement-guard'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { type ActiveCase, activeCase } from '../../test/helpers/case-fixture.js'
import { createExecEvents, guardedShell } from './guarded-shell.js'

const SESSION = 'sess-mcp-example'

describe('guarded_shell', () => {
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

  it('does not run an out-of-scope scan and returns the decision', async () => {
    const events = createExecEvents(g)
    const r = await guardedShell(g, { command: 'nmap 203.0.113.5' }, events)
    expect(r.ran).toBe(false)
    if (r.ran) throw new Error('unreachable')
    expect(r.decision.reason).toBe('OUT_OF_SCOPE')
    expect(r.decision.message).toContain('203.0.113.5')
  })

  it('runs a local command and records the execution in the audit chain', async () => {
    const events = createExecEvents(g)
    const r = await guardedShell(g, { command: 'node -e "console.log(42)"' }, events)
    expect(r.ran).toBe(true)
    if (!r.ran) throw new Error('unreachable')
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain('42')
    await g.audit.flush()
    const dir = join(c.cwd, '.guard', 'audit')
    expect((await verifyAudit(dir)).ok).toBe(true)
    const text = await readFile(join(dir, c.caseId, `${SESSION}.jsonl`), 'utf8')
    const kinds = text
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => (JSON.parse(l) as { kind: string }).kind)
    expect(kinds).toContain('decision')
    expect(kinds).toContain('exec.spawn')
    expect(kinds).toContain('exec.exit')
  })
})
