import { access, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { runCli } from '../../src/cli/main.js'
import { firstRunAckPath, loadFirstRunAck } from '../../src/first-run.js'
import { createCliIo } from '../helpers/cli-io.js'

let cwd: string
let home: string

beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), 'guard-cli-ack-'))
  home = await mkdtemp(join(tmpdir(), 'guard-cli-ack-home-'))
})

afterEach(async () => {
  await rm(cwd, { recursive: true, force: true })
  await rm(home, { recursive: true, force: true })
})

const exists = (p: string) =>
  access(p).then(
    () => true,
    () => false,
  )

describe('engagement-guard ack', () => {
  it('prints the statement and records the acknowledgement on I AGREE', async () => {
    const io = createCliIo({ cwd, env: { GUARD_HOME: home }, stdin: 'I AGREE\n' })
    expect(await runCli(['ack', '--operator', 'alice'], io)).toBe(0)
    expect(io.out()).toContain('operator acknowledgement')
    expect(io.out()).toContain('Type I AGREE to acknowledge:')
    expect(await exists(firstRunAckPath(home))).toBe(true)
    expect((await loadFirstRunAck(home))?.operator).toBe('alice')
  })

  it('records nothing on any other answer and exits 1', async () => {
    const io = createCliIo({ cwd, env: { GUARD_HOME: home }, stdin: 'no\n' })
    expect(await runCli(['ack', '--operator', 'alice'], io)).toBe(1)
    expect(await exists(firstRunAckPath(home))).toBe(false)
  })

  it('is a no-op once acknowledged', async () => {
    await runCli(
      ['ack', '--operator', 'alice'],
      createCliIo({ cwd, env: { GUARD_HOME: home }, stdin: 'I AGREE\n' }),
    )
    const io = createCliIo({ cwd, env: { GUARD_HOME: home }, stdin: '' })
    expect(await runCli(['ack'], io)).toBe(0)
    expect(io.out()).toContain('already acknowledged')
  })
})

describe('engagement-guard ack without a terminal (C1b)', () => {
  it('refuses, records nothing and exits 1 even on I AGREE', async () => {
    const io = createCliIo({ cwd, env: { GUARD_HOME: home }, stdin: 'I AGREE\n', tty: false })
    expect(await runCli(['ack', '--operator', 'alice'], io)).toBe(1)
    expect(io.err()).toContain(
      'refused: ack needs an interactive terminal; a case is attested by a person, not by an agent',
    )
    expect(io.out()).toBe('')
    expect(await exists(firstRunAckPath(home))).toBe(false)
  })
})
