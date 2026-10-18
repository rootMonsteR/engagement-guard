import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { runCli } from '../../src/cli/main.js'
import { type ActiveCase, activeCase } from '../helpers/case-fixture.js'
import { createCliIo, type TestCliIo } from '../helpers/cli-io.js'

let c: ActiveCase

beforeEach(async () => {
  c = await activeCase()
})

afterEach(async () => {
  await c.cleanup()
})

const io = (): TestCliIo =>
  createCliIo({
    cwd: c.cwd,
    env: { GUARD_HOME: c.home, GUARD_OPERATOR: 'alice' },
    now: c.now,
    lookup: c.lookup,
  })

describe('engagement-guard check', () => {
  it('passes an in-scope scan with exit 0', async () => {
    const o = io()
    expect(await runCli(['check', 'nmap 192.0.2.10'], o)).toBe(0)
    expect(o.out().startsWith('pass IN_SCOPE\n')).toBe(true)
    expect(o.out()).toContain('targets: 192.0.2.10 (in-scope)')
  })

  it('denies an out-of-scope scan with exit 2', async () => {
    const o = io()
    expect(await runCli(['check', 'nmap 203.0.113.5'], o)).toBe(2)
    expect(o.out().startsWith('deny OUT_OF_SCOPE\n')).toBe(true)
    expect(o.out()).toContain('targets: 203.0.113.5 (out-of-scope)')
    expect(o.out()).toContain('engagement-guard engagement edit')
  })

  it('asks for a partly authorised range with exit 1', async () => {
    const o = io()
    expect(await runCli(['check', 'nmap 192.0.2.120-140'], o)).toBe(1)
    expect(o.out().startsWith('ask RANGE_NOT_FULLY_AUTHORISED\n')).toBe(true)
  })

  it('accepts the command as several words', async () => {
    const o = io()
    expect(await runCli(['check', 'nmap', '203.0.113.5'], o)).toBe(2)
  })

  it('--json prints the decision as one object', async () => {
    const o = io()
    expect(await runCli(['check', '--json', 'ls'], o)).toBe(0)
    const parsed = JSON.parse(o.out()) as { verdict: string; reason: string; targets: unknown[] }
    expect(parsed.verdict).toBe('pass')
    expect(parsed.reason).toBe('NOT_NETWORK')
    expect(parsed.targets).toEqual([])
  })

  it('--shell powershell asks about a PowerShell network tool', async () => {
    const o = io()
    expect(
      await runCli(['check', '--shell', 'powershell', 'Invoke-WebRequest http://192.0.2.10'], o),
    ).toBe(1)
    expect(o.out().startsWith('ask POWERSHELL_NETWORK_TOOL\n')).toBe(true)
  })

  it('rejects an unknown shell with usage and exit 1', async () => {
    const o = io()
    expect(await runCli(['check', '--shell', 'fish', 'ls'], o)).toBe(1)
    expect(o.err()).toContain('--shell')
  })
})
