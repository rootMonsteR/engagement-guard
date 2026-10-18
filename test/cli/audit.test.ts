import { access, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { createAuditLog } from '../../src/audit/writer.js'
import { runCli } from '../../src/cli/main.js'
import { type ActiveCase, activeCase, TABLE_CASE_ID } from '../helpers/case-fixture.js'
import { createCliIo, type TestCliIo } from '../helpers/cli-io.js'

let c: ActiveCase
let tmp: string

beforeEach(async () => {
  c = await activeCase()
  tmp = await mkdtemp(join(tmpdir(), 'guard-cli-audit-'))
  // One audited decision in the chain.
  expect(await runCli(['check', 'nmap 203.0.113.5'], io())).toBe(2)
})

afterEach(async () => {
  await c.cleanup()
  await rm(tmp, { recursive: true, force: true })
})

const io = (): TestCliIo =>
  createCliIo({
    cwd: c.cwd,
    env: { GUARD_HOME: c.home, GUARD_OPERATOR: 'alice' },
    now: c.now,
    lookup: c.lookup,
  })

const exists = (p: string) =>
  access(p).then(
    () => true,
    () => false,
  )

async function chainFile(): Promise<string> {
  const dir = join(c.cwd, '.guard', 'audit', TABLE_CASE_ID)
  const names = (await readdir(dir)).filter((n) => n.endsWith('.jsonl'))
  expect(names).toHaveLength(1)
  return join(dir, names[0] as string)
}

describe('engagement-guard audit', () => {
  it('verify reports one ok chain and exits 0', async () => {
    const o = io()
    expect(await runCli(['audit', 'verify'], o)).toBe(0)
    const lines = o.out().trim().split('\n')
    expect(lines).toHaveLength(1)
    expect(lines[0]).toMatch(/^ok .*\.jsonl \d+ [0-9a-f]{12}$/)
  })

  it('verify finds a flipped byte and exits 1', async () => {
    const file = await chainFile()
    const text = await readFile(file, 'utf8')
    expect(text).toContain('"operator":"alice"')
    await writeFile(file, text.replace('"operator":"alice"', '"operator":"alicf"'))
    const o = io()
    expect(await runCli(['audit', 'verify'], o)).toBe(1)
    expect(o.out()).toContain('HASH_MISMATCH')
    expect(o.out()).toMatch(/^FAIL /m)
  })

  it('show lists the decision', async () => {
    const o = io()
    expect(await runCli(['audit', 'show', '--tail', '5'], o)).toBe(0)
    expect(o.out()).toMatch(/\bdecision\b.*OUT_OF_SCOPE/)
  })

  it('export writes a bundle and exits 0', async () => {
    const out = join(tmp, 'x.tar.gz')
    const o = io()
    expect(await runCli(['audit', 'export', '--out', out], o)).toBe(0)
    expect(await exists(out)).toBe(true)
    expect(o.out()).toContain('x.tar.gz')
  })
})

describe('engagement-guard audit without a terminal (C1b)', () => {
  it('verify and show still work', async () => {
    const v = createCliIo({ cwd: c.cwd, env: { GUARD_HOME: c.home }, now: c.now, tty: false })
    expect(await runCli(['audit', 'verify'], v)).toBe(0)
    const s = createCliIo({ cwd: c.cwd, env: { GUARD_HOME: c.home }, now: c.now, tty: false })
    expect(await runCli(['audit', 'show'], s)).toBe(0)
    expect(s.out()).toMatch(/OUT_OF_SCOPE/)
  })
})

describe('engagement-guard audit show --tail across chains (M7)', () => {
  it('takes the tail by time, then seq, not by index order', async () => {
    const dir = join(c.cwd, '.guard', 'audit')
    let clock = Date.parse('2026-10-22T08:00:00.000Z')
    const tick = () => new Date((clock += 1000))
    const hook = createAuditLog({ dir, sessionId: 'hook-a', operator: 'alice', now: tick })
    const cli = createAuditLog({ dir, sessionId: 'cli-b', operator: 'alice', now: tick })
    hook.setCase('mix')
    cli.setCase('mix')
    // The hook's chain is indexed first; its records interleave with the CLI's in time.
    for (const [log, tool] of [
      [hook, 'A1'],
      [cli, 'B2'],
      [hook, 'A3'],
      [cli, 'B4'],
      [hook, 'A5'],
      [cli, 'B6'],
    ] as const) {
      await log.append({ kind: 'tool.call', tool })
    }
    // Same instant in one chain: seq decides.
    clock -= 1000
    await cli.append({ kind: 'tool.call', tool: 'B7' })
    const o = io()
    expect(await runCli(['audit', 'show', '--case', 'mix', '--tail', '4'], o)).toBe(0)
    const tools = o
      .out()
      .trim()
      .split('\n')
      .map((l) => l.trim().split(/\s+/)[3])
    expect(tools).toEqual(['B4', 'A5', 'B6', 'B7'])
  })
})
