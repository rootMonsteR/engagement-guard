import {
  copyFile,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  unlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { parseDocument, parse as parseYaml } from 'yaml'
import type { AuditRecord } from '../../src/audit/record.js'
import { verifyAudit } from '../../src/audit/verify.js'
import { type AuditLog, createAuditLog } from '../../src/audit/writer.js'
import { sha256Hex } from '../../src/canonical.js'
import { ENGAGEMENT_PATH } from '../../src/engagement/load.js'
import {
  type Attestation,
  CaseLifecycleError,
  type CaseState,
  createCaseStore,
  protectedCasePaths,
  scopeSnapshotPath,
} from '../../src/engagement/store.js'
import { firstRunAckPath, hostFingerprint, recordFirstRunAck } from '../../src/first-run.js'
import { resolvePaths } from '../../src/paths.js'

const ACME = join(import.meta.dirname, '..', 'fixtures', 'engagements', 'acme-external.yaml')
const CASE_ID = 'acme-ext-2026q4'
/** Wednesday 10:00 in Amsterdam: inside the fixture's window and outside its blackout hours. */
const NOW = new Date('2026-10-21T08:00:00.000Z')
const NEW_ENTRY = '203.0.113.0/24'

let cwd: string
let home: string
let auditDir: string
let audit: AuditLog

const now = () => NOW
const engagementFile = () => join(cwd, ENGAGEMENT_PATH)
const attestation = (operator = 'alice'): Attestation => ({
  operator,
  statementVersion: 'attestation-v1',
  at: NOW.toISOString(),
  hostFingerprint: hostFingerprint(),
})

beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), 'guard-case-store-'))
  home = await mkdtemp(join(tmpdir(), 'guard-case-home-'))
  await mkdir(join(cwd, '.guard'), { recursive: true })
  await copyFile(ACME, engagementFile())
  await recordFirstRunAck(home, 'alice', NOW)
  auditDir = join(cwd, '.guard', 'audit')
  audit = createAuditLog({ dir: auditDir, sessionId: 's-1', operator: 'alice', now })
})

afterEach(async () => {
  await rm(cwd, { recursive: true, force: true })
  await rm(home, { recursive: true, force: true })
})

const store = (withAudit = true) =>
  createCaseStore(withAudit ? { cwd, home, audit, now } : { cwd, home, now })

async function records(): Promise<AuditRecord[]> {
  await audit.flush()
  let names: string[]
  try {
    names = await readdir(join(auditDir, CASE_ID))
  } catch {
    return []
  }
  const out: AuditRecord[] = []
  for (const name of names.sort()) {
    const text = await readFile(join(auditDir, CASE_ID, name), 'utf8')
    for (const line of text.split('\n')) if (line !== '') out.push(JSON.parse(line))
  }
  return out
}

const kinds = async () => (await records()).map((r) => r.kind)

/** Appends an entry to `scope.in` on disk, as an operator editing the file would. */
async function widenScope(): Promise<void> {
  const text = await readFile(engagementFile(), 'utf8')
  const anchor = '    - https://portal.acme-partner.example:8443/app/\n'
  expect(text).toContain(anchor)
  await writeFile(engagementFile(), text.replace(anchor, `${anchor}    - ${NEW_ENTRY}\n`))
}

const hashOf = (s: CaseState) => ('case' in s ? s.case.scopeHash : undefined)

describe('case store: states', () => {
  it('starts unacknowledged for a valid case that was never frozen', async () => {
    const cases = await store()
    expect(cases.state().status).toBe('unacknowledged')
    expect(cases.audited).toBe(true)
    expect(await kinds()).toEqual([])
  })

  it('is none without an engagement file', async () => {
    await unlink(engagementFile())
    expect((await store()).state()).toEqual({ status: 'none' })
  })

  it('is invalid with the validation issues', async () => {
    await writeFile(engagementFile(), 'version: 1\nid: x\n')
    const s = (await store()).state()
    expect(s.status).toBe('invalid')
    if (s.status !== 'invalid') return
    expect(s.path).toBe(engagementFile())
    expect(s.issues.length).toBeGreaterThan(0)
  })

  it('is first-run-required without a first-run acknowledgement, even when the case is frozen', async () => {
    const cases = await store()
    await cases.freeze(attestation())
    expect(cases.state().status).toBe('active')
    await unlink(firstRunAckPath(home))
    expect(await cases.reload()).toEqual({ status: 'first-run-required' })
    expect(cases.state()).toEqual({ status: 'first-run-required' })
  })

  it('refuses to freeze without a first-run acknowledgement', async () => {
    await unlink(firstRunAckPath(home))
    const cases = await store()
    expect(cases.state().status).toBe('first-run-required')
    await expect(cases.freeze(attestation())).rejects.toMatchObject({
      code: 'FIRST_RUN_REQUIRED',
    })
    expect(await readFile(engagementFile(), 'utf8')).toBe(await readFile(ACME, 'utf8'))
  })
})

describe('case store: freeze', () => {
  it('attests and freezes: active, comments kept, snapshot written, audited', async () => {
    const cases = await store()
    const seen: CaseState[] = []
    cases.onChange((s) => seen.push(s))
    const s = await cases.freeze(attestation())
    expect(s.status).toBe('active')
    expect(cases.state()).toBe(s)
    expect(seen.map((x) => x.status)).toEqual(['active'])

    const text = await readFile(engagementFile(), 'utf8')
    expect(text).toContain('# operator callback VPS')
    expect(text).toContain('# nightly backup window, crosses midnight')
    const hash = hashOf(s) as string
    expect(text).toContain(`scope_hash: "${hash}"`)
    expect(parseYaml(text)).toMatchObject({
      acknowledged_by: {
        operator: 'alice',
        at: NOW.toISOString(),
        statement_version: 'attestation-v1',
        host_fingerprint: hostFingerprint(),
      },
      frozen: { at: NOW.toISOString(), by: 'alice', scope_hash: hash },
    })

    const snapshot = scopeSnapshotPath(cwd, CASE_ID, hash)
    expect(snapshot).toBe(join(cwd, '.guard', 'cases', CASE_ID, `${hash}.json`))
    expect(sha256Hex(await readFile(snapshot, 'utf8'))).toBe(hash)

    const recs = await records()
    expect(recs.map((r) => r.kind)).toEqual(['case.freeze', 'case.activate'])
    expect(recs[0]?.caseId).toBe(CASE_ID)
    expect(recs[0]?.data).toMatchObject({
      scopeHash: hash,
      snapshot: `.guard/cases/${CASE_ID}/${hash}.json`,
      attestation: { operator: 'alice', statementVersion: 'attestation-v1' },
    })
    expect(recs[1]?.data).toMatchObject({ scopeHash: hash })
    expect(audit.caseId).toBe(CASE_ID)
    expect((await verifyAudit(auditDir)).ok).toBe(true)
  })

  it('reads the case file and keeps snapshots where the paths say', async () => {
    await mkdir(join(cwd, '.case'))
    await copyFile(ACME, join(cwd, '.case', 'engagement.yaml'))
    const cases = await createCaseStore({
      cwd,
      home,
      now,
      engagementPath: '.case/engagement.yaml',
      casesDir: '.case/cases',
    })
    const s = await cases.freeze(attestation())
    expect(s.status).toBe('active')
    const hash = hashOf(s) as string
    const snapshot = scopeSnapshotPath(cwd, CASE_ID, hash, '.case/cases')
    expect(sha256Hex(await readFile(snapshot, 'utf8'))).toBe(hash)
    expect(await readdir(join(cwd, '.guard'))).not.toContain('cases')
  })

  it('leaves no temporary files next to the case file', async () => {
    await (await store()).freeze(attestation())
    const names = await readdir(join(cwd, '.guard'))
    expect(names.filter((n) => n.includes('tmp'))).toEqual([])
  })

  it('keeps CRLF line endings', async () => {
    const lf = await readFile(ACME, 'utf8')
    await writeFile(engagementFile(), lf.replace(/\n/g, '\r\n'))
    const s = await (await store()).freeze(attestation())
    expect(s.status).toBe('active')
    const text = await readFile(engagementFile(), 'utf8')
    expect(text).toContain('scope_hash: "')
    expect(
      text
        .split('\n')
        .slice(0, -1)
        .every((l) => l.endsWith('\r')),
    ).toBe(true)
  })

  it('is a no-op on an active case', async () => {
    const cases = await store()
    await cases.freeze(attestation())
    const before = await readFile(engagementFile(), 'utf8')
    const s = await cases.freeze(attestation('bob'))
    expect(s.status).toBe('active')
    expect(await readFile(engagementFile(), 'utf8')).toBe(before)
    expect(await kinds()).toEqual(['case.freeze', 'case.activate'])
  })

  it('refuses to freeze a tampered case (the change must go through edit)', async () => {
    const cases = await store()
    await cases.freeze(attestation())
    await widenScope()
    expect((await cases.reload()).status).toBe('tampered')
    const err = await cases.freeze(attestation()).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(CaseLifecycleError)
    expect((err as CaseLifecycleError).code).toBe('SCOPE_TAMPERED')
  })

  it('refuses to freeze an invalid or missing case', async () => {
    const cases = await store()
    await writeFile(engagementFile(), 'version: 1\n')
    await expect(cases.freeze(attestation())).rejects.toMatchObject({ code: 'CASE_INVALID' })
    await unlink(engagementFile())
    await expect(cases.freeze(attestation())).rejects.toMatchObject({ code: 'NO_ACTIVE_CASE' })
  })

  it('works without an audit log', async () => {
    const cases = await store(false)
    expect(cases.audited).toBe(false)
    expect((await cases.freeze(attestation())).status).toBe('active')
    expect(await kinds()).toEqual([])
  })

  it('records case.activate once per activation, not on every reload', async () => {
    const cases = await store()
    await cases.freeze(attestation())
    await cases.reload()
    await cases.reload()
    expect(await kinds()).toEqual(['case.freeze', 'case.activate'])
    // A fresh store (a new session) activating the same case records it again.
    const again = await store()
    expect(again.state().status).toBe('active')
    expect(await kinds()).toEqual(['case.freeze', 'case.activate', 'case.activate'])
  })
})

describe('case store: tamper and audited edit (Review Focus 6)', () => {
  it('detects a scope change on disk and re-attests it with a recorded diff', async () => {
    const cases = await store()
    const frozen = await cases.freeze(attestation())
    const oldHash = hashOf(frozen) as string

    await widenScope()
    const tampered = await cases.reload()
    expect(tampered.status).toBe('tampered')
    if (tampered.status !== 'tampered') return
    expect(tampered.frozenHash).toBe(oldHash)
    expect(tampered.case.scopeHash).not.toBe(oldHash)
    const newHash = tampered.case.scopeHash

    const pending = await cases.pendingDiff()
    expect(pending).toMatchObject({ oldHash, newHash, base: 'verified' })
    expect(pending.diff).toContain(`+ "${NEW_ENTRY}"`)

    const { state, diff } = await cases.edit(attestation())
    expect(state.status).toBe('active')
    expect(hashOf(state)).toBe(newHash)
    expect(diff).toContain(`+ "${NEW_ENTRY}"`)
    expect(diff).toContain('scope.in[5]')

    const text = await readFile(engagementFile(), 'utf8')
    expect(text).toContain(`scope_hash: "${newHash}"`)
    expect(text).toContain('# operator callback VPS')
    expect(sha256Hex(await readFile(scopeSnapshotPath(cwd, CASE_ID, newHash), 'utf8'))).toBe(
      newHash,
    )

    const recs = await records()
    expect(recs.map((r) => r.kind)).toEqual([
      'case.freeze',
      'case.activate',
      'case.edit',
      'case.activate',
    ])
    expect(recs[2]?.data).toMatchObject({
      oldHash,
      newHash,
      baseSnapshot: 'verified',
      diff: [{ op: 'added', path: 'scope.in[5]', value: NEW_ENTRY }],
      attestation: { operator: 'alice', statementVersion: 'attestation-v1' },
    })
    expect((await verifyAudit(auditDir)).ok).toBe(true)
  })

  it('still edits when the base snapshot is missing, and records that the diff is unavailable', async () => {
    const cases = await store()
    const oldHash = hashOf(await cases.freeze(attestation())) as string
    await unlink(scopeSnapshotPath(cwd, CASE_ID, oldHash))
    await widenScope()
    const { state, diff } = await cases.edit(attestation())
    expect(state.status).toBe('active')
    expect(diff).toBe('(base snapshot unavailable or altered)')
    const edit = (await records()).find((r) => r.kind === 'case.edit')
    expect(edit?.data).toMatchObject({
      oldHash,
      diff: null,
      baseSnapshot: 'unavailable',
      diffNote: '(base snapshot unavailable or altered)',
    })
    expect((await verifyAudit(auditDir)).ok).toBe(true)
  })

  it('treats a snapshot whose sha256 does not match its name as altered', async () => {
    const cases = await store()
    const oldHash = hashOf(await cases.freeze(attestation())) as string
    const path = scopeSnapshotPath(cwd, CASE_ID, oldHash)
    await writeFile(path, (await readFile(path, 'utf8')).replace('192.0.2.0/25', '192.0.2.0/24'))
    await widenScope()
    const { diff } = await cases.edit(attestation())
    expect(diff).toBe('(base snapshot unavailable or altered)')
    expect((await records()).find((r) => r.kind === 'case.edit')?.data).toMatchObject({
      baseSnapshot: 'altered',
      diff: null,
    })
  })

  it('refuses to edit a case that was never frozen', async () => {
    const cases = await store()
    await expect(cases.edit(attestation())).rejects.toMatchObject({ code: 'NOT_ACKNOWLEDGED' })
  })

  it('re-attests an unchanged active case with an empty diff', async () => {
    const cases = await store()
    await cases.freeze(attestation())
    const { state, diff } = await cases.edit(attestation('bob'))
    expect(state.status).toBe('active')
    expect(diff).toBe('(no changes)')
    expect(parseYaml(await readFile(engagementFile(), 'utf8'))).toMatchObject({
      frozen: { by: 'bob' },
      acknowledged_by: { operator: 'bob' },
    })
  })
})

describe('case store: onChange', () => {
  it('notifies on state changes only, and unsubscribes', async () => {
    const cases = await store()
    const seen: string[] = []
    const off = cases.onChange((s) => seen.push(s.status))
    await cases.reload()
    expect(seen).toEqual([])
    await cases.freeze(attestation())
    await widenScope()
    await cases.reload()
    expect(seen).toEqual(['active', 'tampered'])
    off()
    await cases.edit(attestation())
    expect(seen).toEqual(['active', 'tampered'])
  })

  it('a throwing listener does not break the store', async () => {
    const cases = await store()
    cases.onChange(() => {
      throw new Error('boom')
    })
    expect((await cases.freeze(attestation())).status).toBe('active')
  })
})

describe('case store: file encoding', () => {
  it('keeps a byte-order mark', async () => {
    const bom = String.fromCharCode(0xfeff)
    await writeFile(engagementFile(), `${bom}${await readFile(ACME, 'utf8')}`)
    const s = await (await store()).freeze(attestation())
    expect(s.status).toBe('active')
    expect((await readFile(engagementFile(), 'utf8')).startsWith(bom)).toBe(true)
  })
})

/** Removes top-level keys from the case file, as a hand edit would. */
async function dropKeys(...keys: string[]): Promise<void> {
  const doc = parseDocument(await readFile(engagementFile(), 'utf8'))
  for (const key of keys) doc.delete(key)
  await writeFile(engagementFile(), String(doc))
}

const editRecord = async () => (await records()).find((r) => r.kind === 'case.edit')

describe('case store: a frozen case stays frozen (fix round 1)', () => {
  it('tampering wins over a missing acknowledged_by block', async () => {
    const cases = await store()
    const oldHash = hashOf(await cases.freeze(attestation())) as string
    await widenScope()
    await dropKeys('acknowledged_by')
    const s = await cases.reload()
    expect(s.status).toBe('tampered')
    if (s.status !== 'tampered') return
    expect(s.frozenHash).toBe(oldHash)
    await expect(cases.freeze(attestation())).rejects.toMatchObject({ code: 'SCOPE_TAMPERED' })
    const { state, diff } = await cases.edit(attestation())
    expect(state.status).toBe('active')
    expect(diff).toContain(`+ "${NEW_ENTRY}"`)
    expect((await editRecord())?.data).toMatchObject({ oldHash, baseSnapshot: 'verified' })
  })

  it('a removed acknowledged_by block alone (same hash) is tampered too; edit re-attests', async () => {
    const cases = await store()
    await cases.freeze(attestation())
    await dropKeys('acknowledged_by')
    const s = await cases.reload()
    expect(s.status).toBe('tampered')
    await expect(cases.freeze(attestation())).rejects.toMatchObject({ code: 'SCOPE_TAMPERED' })
    const { state, diff } = await cases.edit(attestation())
    expect(state.status).toBe('active')
    expect(diff).toBe('(no changes)')
  })

  it('a case with prior snapshots but no frozen block is tampered (un-audited unfreeze, P25)', async () => {
    const cases = await store()
    const oldHash = hashOf(await cases.freeze(attestation())) as string
    await widenScope()
    await dropKeys('frozen', 'acknowledged_by')
    const s = await cases.reload()
    expect(s.status).toBe('tampered')
    if (s.status !== 'tampered') return
    expect(s.frozenHash).toBe(oldHash)
    await expect(cases.freeze(attestation())).rejects.toMatchObject({ code: 'SCOPE_TAMPERED' })
    const { state, diff } = await cases.edit(attestation())
    expect(state.status).toBe('active')
    expect(diff).toContain(`+ "${NEW_ENTRY}"`)
    expect((await editRecord())?.data).toMatchObject({
      oldHash,
      baseSnapshot: 'verified',
      diff: [{ op: 'added', path: 'scope.in[5]', value: NEW_ENTRY }],
    })
    expect((await verifyAudit(auditDir)).ok).toBe(true)
  })

  it('an unfrozen case diffs against the latest attested snapshot, not an older one', async () => {
    const cases = await store()
    await cases.freeze(attestation())
    await widenScope()
    const latest = hashOf((await cases.edit(attestation())).state) as string
    await dropKeys('frozen')
    const s = await cases.reload()
    expect(s.status === 'tampered' && s.frozenHash).toBe(latest)
    expect((await cases.pendingDiff()).diff).toBe('(no changes)')
  })

  it('an unfrozen case whose snapshots were all deleted is unacknowledged again', async () => {
    const cases = await store()
    await cases.freeze(attestation())
    await dropKeys('frozen', 'acknowledged_by')
    await rm(join(cwd, '.guard', 'cases'), { recursive: true, force: true })
    expect((await cases.reload()).status).toBe('unacknowledged')
  })
})

describe('case store: pinned hashes (fix round 1)', () => {
  it('freeze refuses with CASE_CHANGED when the file no longer has the hash the operator saw', async () => {
    const cases = await store()
    await expect(cases.freeze(attestation(), { expectHash: 'f'.repeat(64) })).rejects.toMatchObject(
      { code: 'CASE_CHANGED' },
    )
    expect(await readFile(engagementFile(), 'utf8')).toBe(await readFile(ACME, 'utf8'))
    expect(await kinds()).toEqual([])
  })

  it('freeze proceeds when the pinned hash matches', async () => {
    const cases = await store()
    const s = cases.state()
    const hash = hashOf(s) as string
    expect((await cases.freeze(attestation(), { expectHash: hash })).status).toBe('active')
  })

  it('edit refuses with CASE_CHANGED when the new hash is not the one whose diff was shown', async () => {
    const cases = await store()
    await cases.freeze(attestation())
    await widenScope()
    const pending = await cases.pendingDiff()
    const text = await readFile(engagementFile(), 'utf8')
    await writeFile(engagementFile(), text.replace('rps: 50', 'rps: 500'))
    await expect(
      cases.edit(attestation(), { expectNewHash: pending.newHash }),
    ).rejects.toMatchObject({ code: 'CASE_CHANGED' })
    expect(await kinds()).toEqual(['case.freeze', 'case.activate'])
    expect((await cases.reload()).status).toBe('tampered')
  })
})

describe('protectedCasePaths', () => {
  it('lists the case, snapshot, audit and home security paths as forward-slash globs', () => {
    const paths = protectedCasePaths('/w', resolvePaths({ home: '/h', env: {} }))
    expect(paths).toEqual([
      '/w/.guard/engagement.yaml',
      '/w/.guard/cases/**',
      '/w/.guard/audit/**',
      '/h/first-run.json',
      '/h/keys/**',
    ])
    const bs = String.fromCharCode(92) // a Windows path separator
    const win = resolvePaths({ home: `C:${bs}h${bs}`, env: {} })
    expect(protectedCasePaths(`C:${bs}w`, win)).toEqual([
      'C:/w/.guard/engagement.yaml',
      'C:/w/.guard/cases/**',
      'C:/w/.guard/audit/**',
      'C:/h/first-run.json',
      'C:/h/keys/**',
    ])
  })

  it('takes the workspace directory from the paths', () => {
    expect(
      protectedCasePaths('/w', resolvePaths({ home: '/h', dirName: '.case', env: {} })),
    ).toEqual([
      '/w/.case/engagement.yaml',
      '/w/.case/cases/**',
      '/w/.case/audit/**',
      '/h/first-run.json',
      '/h/keys/**',
    ])
  })
})

describe('case store: tamper reasons (fix round 1)', () => {
  it('names why a frozen case is not active, including a revert to an older attested scope', async () => {
    const cases = await store()
    await cases.freeze(attestation())
    const frozenAtA = await readFile(engagementFile(), 'utf8')
    await widenScope()
    expect(await cases.reload()).toMatchObject({ status: 'tampered', reason: 'scope-changed' })
    await cases.edit(attestation())
    // Restoring the earlier, then-valid file (frozen at A) is an un-audited revert.
    await writeFile(engagementFile(), frozenAtA)
    const s = await cases.reload()
    expect(s).toMatchObject({ status: 'tampered', reason: 'superseded' })
    const { state, diff } = await cases.edit(attestation())
    expect(state.status).toBe('active')
    expect(diff).toContain(`- "${NEW_ENTRY}"`)
    expect((await editRecord())?.data).toMatchObject({ tamperReason: 'scope-changed' })
    const edits = (await records()).filter((r) => r.kind === 'case.edit')
    expect(edits.at(-1)?.data).toMatchObject({ tamperReason: 'superseded' })
  })
})
