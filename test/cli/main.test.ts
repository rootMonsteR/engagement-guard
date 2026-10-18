import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { runCli } from '../../src/cli/main.js'
import { createCliIo } from '../helpers/cli-io.js'

let cwd: string

beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), 'guard-cli-'))
})

afterEach(async () => {
  await rm(cwd, { recursive: true, force: true })
})

describe('runCli', () => {
  it('prints usage and exits 1 on an unknown command', async () => {
    const io = createCliIo({ cwd })
    expect(await runCli(['frobnicate'], io)).toBe(1)
    expect(io.err()).toContain('Usage:')
    expect(io.err()).toContain('frobnicate')
  })

  it('prints usage and exits 1 with no command', async () => {
    const io = createCliIo({ cwd })
    expect(await runCli([], io)).toBe(1)
    expect(io.err()).toContain('Usage:')
  })

  it('--help lists every command and exits 0', async () => {
    const io = createCliIo({ cwd })
    expect(await runCli(['--help'], io)).toBe(0)
    for (const name of ['init', 'engagement', 'ack', 'check', 'hook', 'audit']) {
      expect(io.out()).toMatch(new RegExp(`^\\s+${name}\\b`, 'm'))
    }
  })
})

describe('read-only commands without a terminal (C1b)', () => {
  it('check still decides', async () => {
    const io = createCliIo({ cwd, tty: false })
    expect(await runCli(['check', 'ls'], io)).toBe(0)
    expect(io.err()).not.toContain('refused')
  })

  it('--help still prints the usage', async () => {
    const io = createCliIo({ cwd, tty: false })
    expect(await runCli(['--help'], io)).toBe(0)
  })
})
