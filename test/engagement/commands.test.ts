import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parse as parseYaml } from 'yaml'
import { caseStatusLine, runEngagementCommand } from '../../src/engagement/commands.js'
import { ENGAGEMENT_PATH } from '../../src/engagement/load.js'
import { resolvePaths } from '../../src/paths.js'

const ACME = join(import.meta.dirname, '..', 'fixtures', 'engagements', 'acme-external.yaml')

let cwd: string

beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), 'guard-eng-cmd-'))
})

afterEach(async () => {
  await rm(cwd, { recursive: true, force: true })
})

const run = (...argv: string[]) => runEngagementCommand(argv, { cwd, interactive: false })
const engagementFile = () => join(cwd, ENGAGEMENT_PATH)
const written = async () => parseYaml(await readFile(engagementFile(), 'utf8'))

const COMPLETE = [
  '--id',
  'acme-ext-2026q4',
  '--name',
  'ACME external',
  '--client',
  'ACME Corp',
  '--in',
  'acme.example',
  '--in',
  '192.0.2.0/25',
  '--out',
  '192.0.2.66',
  '--window-start',
  '2026-10-20T08:00:00+02:00',
  '--window-end',
  '2099-10-31T18:00:00+01:00',
  '--timezone',
  'Europe/Amsterdam',
  '--auth-ref',
  'SOW-2026-117',
  '--authorised-by',
  'Dana Reyes, CISO',
  '--signed-on',
  '2026-10-10',
]

describe('engagement new', () => {
  it('scaffolds a pentest case with the default external profile', async () => {
    const r = await run('new')
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain(engagementFile())
    expect(r.output).toContain('engagement-guard engagement validate')
    expect(await written()).toMatchObject({ version: 1, type: 'pentest', profile: 'external' })
  })

  it('writes the requested profile', async () => {
    const r = await run('new', '--profile', 'web')
    expect(r.exitCode).toBe(0)
    expect(await written()).toMatchObject({ type: 'pentest', profile: 'web' })
  })

  it('writes a bug-bounty case', async () => {
    const r = await run('new', '--type', 'bug-bounty', '--profile', 'cloud')
    expect(r.exitCode).toBe(0)
    expect(await written()).toMatchObject({ type: 'bug-bounty', profile: 'cloud' })
  })

  it('refuses a reserved case kind without writing anything', async () => {
    const r = await run('new', '--type', 'incident')
    expect(r.exitCode).toBe(1)
    expect(r.output).toBe('CASE_TYPE_NOT_YET_SUPPORTED: incident arrives in a later release')
    await expect(readFile(engagementFile(), 'utf8')).rejects.toMatchObject({ code: 'ENOENT' })
  })

  it('refuses an unknown case kind or profile', async () => {
    const kind = await run('new', '--type', 'redteam')
    expect(kind.exitCode).toBe(1)
    expect(kind.output).toMatch(/redteam.*pentest.*bug-bounty/)
    const profile = await run('new', '--profile', 'mobile')
    expect(profile.exitCode).toBe(1)
    expect(profile.output).toMatch(/mobile.*external.*web.*internal.*cloud/)
  })

  it('refuses to overwrite an existing file unless --force is given', async () => {
    expect((await run('new')).exitCode).toBe(0)
    const again = await run('new', '--profile', 'web')
    expect(again.exitCode).toBe(1)
    expect(again.output).toBe(`already exists: ${engagementFile()} (use --force to overwrite)`)
    expect(await written()).toMatchObject({ profile: 'external' })

    const forced = await run('new', '--profile', 'web', '--force')
    expect(forced.exitCode).toBe(0)
    expect(await written()).toMatchObject({ profile: 'web' })
  })

  it('fills every supplied value, so a complete scaffold validates', async () => {
    const r = await run('new', ...COMPLETE)
    expect(r.exitCode).toBe(0)
    expect(await written()).toMatchObject({
      id: 'acme-ext-2026q4',
      client: 'ACME Corp',
      authorization: { reference: 'SOW-2026-117', signed_on: '2026-10-10' },
      scope: { in: ['acme.example', '192.0.2.0/25'], out: ['192.0.2.66'] },
    })
    const v = await run('validate')
    expect(v.exitCode).toBe(0)
    expect(v.output).toBe('valid: acme-ext-2026q4 (0 warnings)')
  })

  it('reports an unknown option with the usage', async () => {
    const r = await run('new', '--bogus')
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/--bogus/)
    expect(r.output).toMatch(/Usage: engagement/)
  })
})

describe('engagement validate', () => {
  it('lists every placeholder of a fresh scaffold and exits 1', async () => {
    await run('new')
    const r = await run('validate')
    expect(r.exitCode).toBe(1)
    const [head, ...lines] = r.output.split('\n')
    expect(head).toBe(`invalid: ${engagementFile()} (10 errors, 0 warnings)`)
    expect(lines).toHaveLength(10)
    expect(lines).toContain(
      "error client PLACEHOLDER_VALUE: 'client' is still a placeholder (TODO)",
    )
    for (const line of lines) expect(line).toMatch(/^error \S+ PLACEHOLDER_VALUE: /)
  })

  it('validates a file given with --file (relative to the cwd)', async () => {
    await writeFile(join(cwd, 'acme.yaml'), await readFile(ACME, 'utf8'))
    const r = await run('validate', '--file', 'acme.yaml')
    expect(r.exitCode).toBe(0)
    expect(r.output.startsWith('valid: acme-ext-2026q4 (')).toBe(true)
  })

  it('validates an absolute --file path', async () => {
    const r = await run('validate', '--file', ACME)
    expect(r.exitCode).toBe(0)
    expect(r.output.startsWith('valid: acme-ext-2026q4 (')).toBe(true)
  })

  it('lists errors before warnings', async () => {
    const text = (await readFile(ACME, 'utf8'))
      .replace('    - acme.example\n', '    - acme.example\n    - 10.0.0.0/8\n')
      .replace('client: ACME Corp (fictional)', 'client: TODO')
    await mkdir(join(cwd, '.guard'))
    await writeFile(engagementFile(), text)
    const r = await run('validate')
    expect(r.exitCode).toBe(1)
    const [head, ...lines] = r.output.split('\n')
    expect(head).toMatch(/^invalid: .* \(1 error, [1-9]\d* warnings?\)$/)
    expect(lines[0]).toMatch(/^error client PLACEHOLDER_VALUE: /)
    expect(lines.slice(1).every((l) => l.startsWith('warning '))).toBe(true)
    expect(lines).toContainEqual(
      expect.stringMatching(/^warning scope\.in\[1\] PRIVATE_IN_EXTERNAL: /),
    )
  })

  it('reports a whole-document issue with a readable path', async () => {
    await mkdir(join(cwd, '.guard'))
    await writeFile(engagementFile(), 'version: [1\n')
    const r = await run('validate')
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/\nerror \(document\) YAML_SYNTAX: line \d+/)
  })

  it('reports a missing file with the command that creates one', async () => {
    const r = await run('validate')
    expect(r.exitCode).toBe(1)
    expect(r.output).toBe(`missing: ${engagementFile()} — run: engagement-guard init`)
  })

  it('reports a missing --file', async () => {
    const r = await run('validate', '--file', 'nope.yaml')
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/^missing: .*nope\.yaml/)
  })
})

describe('engagement (dispatch)', () => {
  it('prints the usage for an unknown or missing subcommand and exits 1', async () => {
    for (const argv of [['frobnicate'], []]) {
      const r = await runEngagementCommand(argv, { cwd, interactive: false })
      expect(r.exitCode).toBe(1)
      expect(r.output).toMatch(/Usage: engagement <new\|validate\|show\|freeze\|edit\|load>/)
    }
  })

  it('prints the usage on --help and exits 0', async () => {
    const r = await run('--help')
    expect(r.exitCode).toBe(0)
    expect(r.output).toMatch(/Usage: engagement <new\|validate\|show\|freeze\|edit\|load>/)
    expect(r.output).toMatch(/--profile/)
  })
})

describe('engagement commands with custom paths', () => {
  const paths = resolvePaths({ dirName: '.case', commandHint: 'my-tool edit', env: {} })
  const runIn = (...argv: string[]) =>
    runEngagementCommand(argv, { cwd, interactive: false, paths })

  it('new writes <dirName>/engagement.yaml and names it', async () => {
    const r = await runIn('new')
    expect(r.exitCode).toBe(0)
    const file = join(cwd, '.case', 'engagement.yaml')
    expect(r.output).toContain(file)
    expect(parseYaml(await readFile(file, 'utf8'))).toMatchObject({ version: 1 })
  })

  it('validate reads <dirName>/engagement.yaml by default', async () => {
    const r = await runIn('validate')
    expect(r.exitCode).toBe(1)
    expect(r.output).toContain(join(cwd, '.case', 'engagement.yaml'))
  })

  it('the usage names <dirName>/engagement.yaml', async () => {
    const r = await runIn('--help')
    expect(r.output).toContain('.case/engagement.yaml')
    expect(r.output).not.toContain('.guard/')
  })

  it('caseStatusLine takes the engagement path and the command hint', () => {
    expect(caseStatusLine({ status: 'none' }, paths)).toContain('no .case/engagement.yaml')
    expect(caseStatusLine({ status: 'none' })).toContain('no .guard/engagement.yaml')
  })
})
