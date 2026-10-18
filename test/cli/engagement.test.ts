import { access, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { runCli } from '../../src/cli/main.js'
import { type ActiveCase, activeCase, TABLE_CASE_ID } from '../helpers/case-fixture.js'
import { createCliIo } from '../helpers/cli-io.js'

describe('engagement-guard engagement on a scaffold', () => {
  let cwd: string
  let home: string

  beforeEach(async () => {
    cwd = await mkdtemp(join(tmpdir(), 'guard-cli-eng-'))
    home = await mkdtemp(join(tmpdir(), 'guard-cli-eng-home-'))
    await runCli(['init', '--id', 'acme'], createCliIo({ cwd, env: { GUARD_HOME: home } }))
  })

  afterEach(async () => {
    await rm(cwd, { recursive: true, force: true })
    await rm(home, { recursive: true, force: true })
  })

  it('validate lists the issues of an unfinished file and exits 1', async () => {
    const io = createCliIo({ cwd, env: { GUARD_HOME: home } })
    expect(await runCli(['engagement', 'validate'], io)).toBe(1)
    expect(io.out()).toMatch(/TODO|PLACEHOLDER/i)
  })

  it('prints the engagement usage on a bad subcommand', async () => {
    const io = createCliIo({ cwd, env: { GUARD_HOME: home } })
    expect(await runCli(['engagement', 'bogus'], io)).toBe(1)
    expect(io.out()).toContain('Usage: engagement')
  })
})

describe('engagement-guard engagement on an acknowledged, unfrozen case', () => {
  let c: ActiveCase

  beforeEach(async () => {
    c = await activeCase({ freeze: false })
  })

  afterEach(async () => {
    await c.cleanup()
  })

  it('freeze --attest activates the case and writes case.freeze to the audit chain', async () => {
    const io = createCliIo({
      cwd: c.cwd,
      env: { GUARD_HOME: c.home, GUARD_OPERATOR: 'alice' },
      now: c.now,
    })
    expect(await runCli(['engagement', 'freeze', '--attest', TABLE_CASE_ID], io)).toBe(0)
    expect(io.out()).not.toContain('not audited')
    const dir = join(c.cwd, '.guard', 'audit', TABLE_CASE_ID)
    const files = (await readdir(dir)).filter((n) => n.endsWith('.jsonl'))
    expect(files).toHaveLength(1)
    const text = await readFile(join(dir, files[0] as string), 'utf8')
    const kinds = text
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => (JSON.parse(l) as { kind: string }).kind)
    expect(kinds).toContain('case.freeze')
    expect(kinds).toContain('case.activate')
  })
})

describe('engagement-guard engagement on an active case', () => {
  let c: ActiveCase

  beforeEach(async () => {
    c = await activeCase()
  })

  afterEach(async () => {
    await c.cleanup()
  })

  it('validate exits 0', async () => {
    const io = createCliIo({ cwd: c.cwd, env: { GUARD_HOME: c.home }, now: c.now })
    expect(await runCli(['engagement', 'validate'], io)).toBe(0)
  })

  it('show prints the status line with the case id', async () => {
    const io = createCliIo({ cwd: c.cwd, env: { GUARD_HOME: c.home }, now: c.now })
    expect(await runCli(['engagement', 'show'], io)).toBe(0)
    expect(io.out()).toContain('status: active')
    expect(io.out()).toContain(TABLE_CASE_ID)
  })
})

const REFUSED = (command: string) =>
  `refused: ${command} needs an interactive terminal; a case is attested by a person, not by an agent`

const exists = (p: string) =>
  access(p).then(
    () => true,
    () => false,
  )

describe('engagement-guard engagement without a terminal (C1b)', () => {
  describe('on an empty workspace', () => {
    let cwd: string
    let home: string

    beforeEach(async () => {
      cwd = await mkdtemp(join(tmpdir(), 'guard-cli-eng-tty-'))
      home = await mkdtemp(join(tmpdir(), 'guard-cli-eng-tty-home-'))
    })

    afterEach(async () => {
      await rm(cwd, { recursive: true, force: true })
      await rm(home, { recursive: true, force: true })
    })

    it('new refuses and writes nothing', async () => {
      const io = createCliIo({ cwd, env: { GUARD_HOME: home }, tty: false })
      expect(await runCli(['engagement', 'new', '--id', 'acme'], io)).toBe(1)
      expect(io.err()).toContain(REFUSED('engagement new'))
      expect(await readdir(cwd)).toEqual([])
    })
  })

  describe('on an acknowledged, unfrozen case', () => {
    let c: ActiveCase

    beforeEach(async () => {
      c = await activeCase({ freeze: false })
    })

    afterEach(async () => {
      await c.cleanup()
    })

    it('freeze --attest refuses: the file is unchanged and nothing is audited', async () => {
      const file = join(c.cwd, '.guard', 'engagement.yaml')
      const before = await readFile(file, 'utf8')
      const io = createCliIo({
        cwd: c.cwd,
        env: { GUARD_HOME: c.home, GUARD_OPERATOR: 'alice' },
        now: c.now,
        tty: false,
      })
      expect(await runCli(['engagement', 'freeze', '--attest', TABLE_CASE_ID], io)).toBe(1)
      expect(io.err()).toContain(REFUSED('engagement freeze'))
      expect(await readFile(file, 'utf8')).toBe(before)
      expect(await exists(join(c.cwd, '.guard', 'audit'))).toBe(false)
    })
  })

  describe('on an active case', () => {
    let c: ActiveCase

    beforeEach(async () => {
      c = await activeCase()
    })

    afterEach(async () => {
      await c.cleanup()
    })

    const io = () =>
      createCliIo({
        cwd: c.cwd,
        env: { GUARD_HOME: c.home, GUARD_OPERATOR: 'alice' },
        now: c.now,
        tty: false,
      })

    it('edit --attest refuses on a changed scope: the file is unchanged and nothing is audited', async () => {
      const file = join(c.cwd, '.guard', 'engagement.yaml')
      const text = await readFile(file, 'utf8')
      const changed = text.replace(
        '    - 192.0.2.0/25\n',
        '    - 192.0.2.0/25\n    - 192.0.2.128/25\n',
      )
      expect(changed).not.toBe(text)
      await writeFile(file, changed)
      const o = io()
      expect(await runCli(['engagement', 'edit', '--attest', TABLE_CASE_ID], o)).toBe(1)
      expect(o.err()).toContain(REFUSED('engagement edit'))
      expect(await readFile(file, 'utf8')).toBe(changed)
      expect(await exists(join(c.cwd, '.guard', 'audit'))).toBe(false)
    })

    it('load refuses and audits nothing', async () => {
      const o = io()
      expect(await runCli(['engagement', 'load'], o)).toBe(1)
      expect(o.err()).toContain(REFUSED('engagement load'))
      expect(await exists(join(c.cwd, '.guard', 'audit'))).toBe(false)
    })

    it('show and validate still work', async () => {
      const show = io()
      expect(await runCli(['engagement', 'show'], show)).toBe(0)
      expect(show.out()).toContain('status: active')
      expect(show.err()).toBe('')
      const validate = io()
      expect(await runCli(['engagement', 'validate'], validate)).toBe(0)
    })
  })
})
