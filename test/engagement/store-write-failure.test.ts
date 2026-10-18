import { copyFile, mkdir, mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ENGAGEMENT_PATH } from '../../src/engagement/load.js'
import { type Attestation, createCaseStore, scopeSnapshotPath } from '../../src/engagement/store.js'
import { hostFingerprint, recordFirstRunAck } from '../../src/first-run.js'
import { writeFileAtomic } from '../../src/fs-util.js'

// Fix round 3: a failure after the snapshot is written (rename refused, e.g. EPERM/EBUSY on
// Windows or a synced folder) must not leave attestation history this operation created.
vi.mock('../../src/fs-util.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../../src/fs-util.js')>()
  return { ...real, writeFileAtomic: vi.fn(real.writeFileAtomic) }
})

const ACME = join(import.meta.dirname, '..', 'fixtures', 'engagements', 'acme-external.yaml')
const CASE_ID = 'acme-ext-2026q4'
const NOW = new Date('2026-10-21T08:00:00.000Z')
const now = () => NOW

let cwd: string
let home: string
let realWrite: typeof writeFileAtomic

const engagementFile = () => join(cwd, ENGAGEMENT_PATH)
const casesDir = () => join(cwd, '.guard', 'cases', CASE_ID)
const attestation = (): Attestation => ({
  operator: 'alice',
  statementVersion: 'attestation-v1',
  at: NOW.toISOString(),
  hostFingerprint: hostFingerprint(),
})
const snapshots = async () =>
  (await readdir(casesDir()).catch(() => [] as string[])).filter((n) => n.endsWith('.json'))

/** Makes the next write of the case file fail as a refused rename would. */
function failCaseFileWrite(): void {
  vi.mocked(writeFileAtomic).mockImplementation(async (path, text, mode) => {
    if (path === engagementFile()) {
      throw Object.assign(new Error(`EPERM: operation not permitted, rename '${path}'`), {
        code: 'EPERM',
      })
    }
    return realWrite(path, text, mode)
  })
}

beforeEach(async () => {
  const actual =
    await vi.importActual<typeof import('../../src/fs-util.js')>('../../src/fs-util.js')
  realWrite = actual.writeFileAtomic
  vi.mocked(writeFileAtomic).mockImplementation(realWrite)
  cwd = await mkdtemp(join(tmpdir(), 'guard-case-wfail-'))
  home = await mkdtemp(join(tmpdir(), 'guard-case-wfail-home-'))
  await mkdir(join(cwd, '.guard'), { recursive: true })
  await copyFile(ACME, engagementFile())
  await recordFirstRunAck(home, 'alice', NOW)
})

afterEach(async () => {
  await rm(cwd, { recursive: true, force: true })
  await rm(home, { recursive: true, force: true })
})

describe('case store: a failed rename leaves no attestation history it created', () => {
  it('first freeze: the error surfaces, no snapshot remains, the case stays unacknowledged', async () => {
    const cases = await createCaseStore({ cwd, home, now })
    failCaseFileWrite()
    await expect(cases.freeze(attestation())).rejects.toThrow(/EPERM/)
    expect(await snapshots()).toEqual([])
    expect(await readFile(engagementFile(), 'utf8')).toBe(await readFile(ACME, 'utf8'))
    expect((await cases.reload()).status).toBe('unacknowledged')
  })

  it('edit of a case attested at the same hash: the pre-existing snapshot survives', async () => {
    const cases = await createCaseStore({ cwd, home, now })
    const frozen = await cases.freeze(attestation())
    const hash = frozen.status === 'active' ? frozen.case.scopeHash : ''
    const path = scopeSnapshotPath(cwd, CASE_ID, hash)
    const before = await readFile(path, 'utf8')
    failCaseFileWrite()
    await expect(cases.edit(attestation())).rejects.toThrow(/EPERM/)
    expect(await readFile(path, 'utf8')).toBe(before)
    expect((await cases.reload()).status).toBe('active')
  })

  it('a CASE_CHANGED refusal leaves no snapshot', async () => {
    const cases = await createCaseStore({ cwd, home, now })
    await expect(cases.freeze(attestation(), { expectHash: 'f'.repeat(64) })).rejects.toMatchObject(
      { code: 'CASE_CHANGED' },
    )
    expect(await snapshots()).toEqual([])
    expect((await cases.reload()).status).toBe('unacknowledged')
  })
})
