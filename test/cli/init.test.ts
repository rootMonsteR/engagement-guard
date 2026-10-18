import { access, mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { runCli } from '../../src/cli/main.js'
import { createCliIo } from '../helpers/cli-io.js'

let cwd: string
let home: string

beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), 'guard-cli-init-'))
  home = await mkdtemp(join(tmpdir(), 'guard-cli-init-home-'))
})

afterEach(async () => {
  await rm(cwd, { recursive: true, force: true })
  await rm(home, { recursive: true, force: true })
})

const ARGS = [
  'init',
  '--type',
  'pentest',
  '--profile',
  'external',
  '--id',
  'acme',
  '--name',
  'Acme',
  '--client',
  'Acme',
]

describe('engagement-guard init', () => {
  it('writes .guard/engagement.yaml with TODO markers', async () => {
    const io = createCliIo({ cwd, env: { GUARD_HOME: home } })
    expect(await runCli(ARGS, io)).toBe(0)
    const text = await readFile(join(cwd, '.guard', 'engagement.yaml'), 'utf8')
    expect(text).toContain('TODO')
    expect(text).toContain('id: "acme"')
    expect(io.out()).toContain('engagement.yaml')
  })

  it('refuses to overwrite an existing file', async () => {
    await runCli(ARGS, createCliIo({ cwd, env: { GUARD_HOME: home } }))
    const io = createCliIo({ cwd, env: { GUARD_HOME: home } })
    expect(await runCli(ARGS, io)).toBe(1)
    expect(io.out()).toContain('already exists')
  })
})

describe('engagement-guard init without a terminal (C1b)', () => {
  it('refuses, writes nothing and exits 1', async () => {
    const io = createCliIo({ cwd, env: { GUARD_HOME: home }, tty: false })
    expect(await runCli(ARGS, io)).toBe(1)
    expect(io.err()).toContain(
      'refused: init needs an interactive terminal; a case is attested by a person, not by an agent',
    )
    expect(await readdir(cwd)).toEqual([])
    await expect(access(join(cwd, '.guard', 'engagement.yaml'))).rejects.toThrow()
  })
})
