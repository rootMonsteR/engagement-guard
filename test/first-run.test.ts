import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { hostname, platform, tmpdir, userInfo } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { sha256Hex } from '../src/canonical.js'
import {
  ATTESTATION_STATEMENT_VERSION,
  FIRST_RUN_STATEMENT_VERSION,
  firstRunAckPath,
  hostFingerprint,
  loadFirstRunAck,
  readAttestationStatement,
  readFirstRunStatement,
  recordFirstRunAck,
  resolveOperator,
} from '../src/first-run.js'

/** Pinned (as in test/legal/statements.test.ts): a wording change must bump the version. */
const FIRST_RUN_V1_SHA256 = '65fcc27572cfd5324999f5079f0bf7e75a963ac164823f93c23a3ff1acfb4aac'
const ATTESTATION_V1_SHA256 = '413d9d5f0c4086b7a787706f6427c365f97b7dcf92ccd91ffd0a46b4c87797c9'

const NOW = new Date('2026-10-21T08:00:00.000Z')

let home: string

beforeEach(async () => {
  home = await mkdtemp(join(tmpdir(), 'guard-first-run-'))
})

afterEach(async () => {
  await rm(home, { recursive: true, force: true })
})

describe('statements', () => {
  it('reads the first-run statement with its version and pinned sha256', async () => {
    const s = await readFirstRunStatement()
    expect(s.version).toBe(FIRST_RUN_STATEMENT_VERSION)
    expect(s.version).toBe('first-run-v1')
    expect(s.sha256).toBe(sha256Hex(s.text))
    expect(s.sha256).toBe(FIRST_RUN_V1_SHA256)
    expect(s.text).toMatch(/obligations/i)
    expect(s.text).toMatch(/audit log/i)
  })

  it('reads the attestation statement with its pinned sha256', async () => {
    const s = await readAttestationStatement()
    expect(s.version).toBe(ATTESTATION_STATEMENT_VERSION)
    expect(s.version).toBe('attestation-v1')
    expect(s.sha256).toBe(ATTESTATION_V1_SHA256)
    expect(s.text).not.toContain('\r')
  })
})

describe('first-run acknowledgement', () => {
  it('is undefined when nothing was recorded', async () => {
    expect(await loadFirstRunAck(home)).toBeUndefined()
  })

  it('round-trips through <home>/first-run.json', async () => {
    const ack = await recordFirstRunAck(home, 'alice', NOW)
    const statement = await readFirstRunStatement()
    expect(ack).toEqual({
      statementVersion: 'first-run-v1',
      statementSha256: statement.sha256,
      operator: 'alice',
      at: '2026-10-21T08:00:00.000Z',
      hostFingerprint: hostFingerprint(),
    })
    expect(firstRunAckPath(home)).toBe(join(home, 'first-run.json'))
    expect(JSON.parse(await readFile(firstRunAckPath(home), 'utf8'))).toEqual(ack)
    expect(await loadFirstRunAck(home)).toEqual(ack)
  })

  it.skipIf(process.platform === 'win32')('writes the file with mode 0600', async () => {
    await recordFirstRunAck(home, 'alice', NOW)
    expect((await stat(firstRunAckPath(home))).mode & 0o777).toBe(0o600)
  })

  it('is undefined when the statement text changed without a version bump (sha mismatch)', async () => {
    const ack = await recordFirstRunAck(home, 'alice', NOW)
    const statement = await readFirstRunStatement()
    const edited = { ...ack, statementSha256: sha256Hex(`${statement.text}\nedited`) }
    await writeFile(firstRunAckPath(home), JSON.stringify(edited))
    expect(await loadFirstRunAck(home)).toBeUndefined()
  })

  it('is undefined when the acknowledged version is not the current one', async () => {
    const ack = await recordFirstRunAck(home, 'alice', NOW)
    await writeFile(
      firstRunAckPath(home),
      JSON.stringify({ ...ack, statementVersion: 'first-run-v0' }),
    )
    expect(await loadFirstRunAck(home)).toBeUndefined()
  })

  it('is undefined for a malformed or incomplete file', async () => {
    await recordFirstRunAck(home, 'alice', NOW)
    await writeFile(firstRunAckPath(home), '{not json')
    expect(await loadFirstRunAck(home)).toBeUndefined()
    await writeFile(firstRunAckPath(home), JSON.stringify({ operator: 'alice' }))
    expect(await loadFirstRunAck(home)).toBeUndefined()
  })

  it('refuses an empty operator name', async () => {
    await expect(recordFirstRunAck(home, '  ', NOW)).rejects.toThrow(/operator/)
    expect(await loadFirstRunAck(home)).toBeUndefined()
  })

  it('re-recording replaces the previous acknowledgement', async () => {
    await recordFirstRunAck(home, 'alice', NOW)
    await recordFirstRunAck(home, 'bob', new Date('2026-10-22T08:00:00.000Z'))
    expect(await loadFirstRunAck(home)).toMatchObject({ operator: 'bob' })
  })
})

describe('operator identity', () => {
  it('fingerprints the host as 16 hex chars of sha256(hostname|platform|username)', () => {
    const expected = sha256Hex(`${hostname()}|${platform()}|${userInfo().username}`).slice(0, 16)
    expect(hostFingerprint()).toBe(expected)
    expect(hostFingerprint()).toMatch(/^[0-9a-f]{16}$/)
  })

  it('takes GUARD_OPERATOR (or the named variable), else the OS user name', () => {
    expect(resolveOperator({ GUARD_OPERATOR: 'carol' })).toBe('carol')
    expect(resolveOperator({ GUARD_OPERATOR: '  ' })).toBe(userInfo().username)
    expect(resolveOperator({})).toBe(userInfo().username)
    expect(resolveOperator({ MY_OPERATOR: 'dave', GUARD_OPERATOR: 'carol' }, 'MY_OPERATOR')).toBe(
      'dave',
    )
  })
})

describe('first-run acknowledgement: host binding (fix round 1)', () => {
  it('is undefined when the file was recorded on another host or account', async () => {
    const ack = await recordFirstRunAck(home, 'alice', NOW)
    await writeFile(
      firstRunAckPath(home),
      JSON.stringify({ ...ack, hostFingerprint: '0000000000000000' }),
    )
    expect(await loadFirstRunAck(home)).toBeUndefined()
  })
})

describe('first-run statement content (fix round 1)', () => {
  it('describes this guard and its ack command, not a host product', async () => {
    const text = (await readFirstRunStatement()).text
    expect(text).toContain('engagement-guard ack')
    expect(text).not.toContain('--no-security')
    expect(text).not.toMatch(/docker/i)
  })
})
