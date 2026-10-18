import { createHash } from 'node:crypto'
import { appendFile, chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { gunzipSync, gzipSync } from 'node:zlib'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { exportAudit, verifyAuditBundle } from '../../src/audit/export.js'
import { readTarGz, TarTooLargeError, writeTarGz } from '../../src/audit/tar.js'
import { verifyAudit } from '../../src/audit/verify.js'
import { createAuditLog } from '../../src/audit/writer.js'

let root: string
let dir: string
let home: string

const now = () => new Date('2026-10-21T09:30:00.000Z')
const sha256 = (b: Uint8Array | string) => createHash('sha256').update(b).digest('hex')
const text = (b: Uint8Array) => Buffer.from(b).toString('utf8')

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'guard-audit-export-'))
  dir = join(root, 'ws', '.guard', 'audit')
  home = join(root, 'home')
  const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice', now })
  await audit.append({ kind: 'session.start' }) // no-case: must not be exported
  audit.setCase('acme-2026')
  await audit.append({ kind: 'case.activate' })
  await audit.append({ kind: 'decision', command: 'nmap -sV 192.0.2.10' })
  const other = createAuditLog({ dir, sessionId: 's-2', operator: 'alice', now })
  other.setCase('acme-2026')
  await other.append({ kind: 'decision', command: 'curl https://acme.example' })
})

afterEach(async () => {
  await rm(root, { recursive: true, force: true })
})

const doExport = (out = join(root, 'out', 'acme.tar.gz')) =>
  exportAudit({ dir, caseId: 'acme-2026', out, home, operator: 'alice', now })

async function rewriteBundle(
  path: string,
  edit: (entries: { path: string; data: Uint8Array }[]) => void,
): Promise<string> {
  const entries = await readTarGz(await readFile(path))
  edit(entries)
  const out = `${path}.tampered.tar.gz`
  await writeFile(out, await writeTarGz(entries, now()))
  return out
}

describe('exportAudit', () => {
  it('writes a signed bundle with the case logs, filtered index, manifest and public key', async () => {
    const { path, manifestSha256 } = await doExport()
    const entries = await readTarGz(await readFile(path))
    const names = entries.map((e) => e.path)
    expect(names).toEqual([
      'manifest.json',
      'manifest.sig',
      'audit-public-key.pem',
      'index.jsonl',
      'audit/acme-2026/s-1.jsonl',
      'audit/acme-2026/s-2.jsonl',
    ])
    const byName = new Map(entries.map((e) => [e.path, e.data]))
    const manifestBytes = byName.get('manifest.json') as Uint8Array
    expect(sha256(manifestBytes)).toBe(manifestSha256)
    const manifest = JSON.parse(text(manifestBytes))
    expect(manifest).toMatchObject({
      caseId: 'acme-2026',
      createdAt: '2026-10-21T09:30:00.000Z',
      operator: 'alice',
      verify: { ok: true },
    })
    for (const f of manifest.files) {
      const data = byName.get(f.path) as Uint8Array
      expect(sha256(data), f.path).toBe(f.sha256)
      expect(data.byteLength).toBe(f.bytes)
    }
    expect(
      manifest.files.find((f: { path: string }) => f.path === 'audit/acme-2026/s-1.jsonl'),
    ).toMatchObject({
      records: 2,
      head: expect.stringMatching(/^[0-9a-f]{64}$/),
    })
    const index = text(byName.get('index.jsonl') as Uint8Array)
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => JSON.parse(l))
    expect(index.map((l) => l.caseId)).toEqual(['acme-2026', 'acme-2026'])
    expect(text(byName.get('audit-public-key.pem') as Uint8Array)).toContain('BEGIN PUBLIC KEY')
    // the round trip through the tar reader is byte-exact
    expect(text(byName.get('audit/acme-2026/s-1.jsonl') as Uint8Array)).toBe(
      await readFile(join(dir, 'acme-2026', 's-1.jsonl'), 'utf8'),
    )
  })

  it('verifies: signatureValid and ok', async () => {
    const { path } = await doExport()
    const report = await verifyAuditBundle(path)
    expect(report.signatureValid).toBe(true)
    expect(report.ok).toBe(true)
    expect(report.files.map((f) => f.path)).toEqual([
      'audit/acme-2026/s-1.jsonl',
      'audit/acme-2026/s-2.jsonl',
    ])
    expect(report.files.map((f) => f.records)).toEqual([2, 1])
  })

  it('one changed byte in a bundled jsonl: signature still valid, but not ok (sha mismatch)', async () => {
    const { path } = await doExport()
    const tampered = await rewriteBundle(path, (entries) => {
      const e = entries.find((x) => x.path === 'audit/acme-2026/s-1.jsonl')
      if (!e) throw new Error('missing entry')
      const copy = Buffer.from(e.data)
      const at = copy.indexOf('192.0.2.10')
      copy[at + 9] = '9'.charCodeAt(0)
      e.data = copy
    })
    const report = await verifyAuditBundle(tampered)
    expect(report.signatureValid).toBe(true)
    expect(report.ok).toBe(false)
    const errors = report.files.flatMap((f) => f.errors.map((e) => `${f.path}:${e.code}`))
    expect(errors).toContain('audit/acme-2026/s-1.jsonl:HASH_MISMATCH')
  })

  it('a changed manifest: signature invalid', async () => {
    const { path } = await doExport()
    const tampered = await rewriteBundle(path, (entries) => {
      const e = entries.find((x) => x.path === 'manifest.json')
      if (!e) throw new Error('missing entry')
      e.data = Buffer.from(text(e.data).replace('"operator": "alice"', '"operator": "mallory"'))
    })
    const report = await verifyAuditBundle(tampered)
    expect(report.signatureValid).toBe(false)
    expect(report.ok).toBe(false)
  })

  it('a missing bundled file is reported', async () => {
    const { path } = await doExport()
    const tampered = await rewriteBundle(path, (entries) => {
      entries.splice(
        entries.findIndex((x) => x.path === 'audit/acme-2026/s-2.jsonl'),
        1,
      )
    })
    const report = await verifyAuditBundle(tampered)
    expect(report.ok).toBe(false)
    expect(report.files.flatMap((f) => f.errors.map((e) => e.code))).toContain('MISSING_FILE')
  })

  it('a garbage file is reported, never thrown', async () => {
    const junk = join(root, 'junk.tar.gz')
    await writeFile(junk, 'not a bundle')
    const report = await verifyAuditBundle(junk)
    expect(report).toMatchObject({ ok: false, signatureValid: false })
    expect(report.files[0]?.errors[0]?.code).toBe('PARSE_ERROR')
  })

  it('creates the signing key once at <home>/keys/audit-ed25519.pem (0600) and reuses it', async () => {
    const first = await doExport(join(root, 'out', 'a.tar.gz'))
    const keyPath = join(home, 'keys', 'audit-ed25519.pem')
    const key = await readFile(keyPath, 'utf8')
    expect(key).toContain('PRIVATE KEY')
    if (process.platform !== 'win32') expect((await stat(keyPath)).mode & 0o777).toBe(0o600)
    const second = await doExport(join(root, 'out', 'b.tar.gz'))
    expect(await readFile(keyPath, 'utf8')).toBe(key)
    const pub = async (p: string) =>
      text(
        (await readTarGz(await readFile(p))).find((e) => e.path === 'audit-public-key.pem')?.data ??
          new Uint8Array(),
      )
    expect(await pub(first.path)).toBe(await pub(second.path))
  })

  it('never overwrites an existing bundle', async () => {
    const out = join(root, 'out', 'acme.tar.gz')
    await doExport(out)
    await expect(doExport(out)).rejects.toThrow(/exists/i)
  })

  it('refuses to export a case whose log does not verify', async () => {
    const file = join(dir, 'acme-2026', 's-1.jsonl')
    const content = await readFile(file, 'utf8')
    await writeFile(file, content.replace('192.0.2.10', '192.0.2.19'))
    await expect(doExport()).rejects.toThrow(/verif/i)
  })

  it('refuses to export a case with no audit records', async () => {
    await expect(
      exportAudit({
        dir,
        caseId: 'unknown-case',
        out: join(root, 'x.tar.gz'),
        home,
        operator: 'alice',
        now,
      }),
    ).rejects.toThrow(/no audit/i)
  })

  it('writes an audit.export record into the case log', async () => {
    const { manifestSha256 } = await doExport()
    const report = await verifyAudit(dir, { caseId: 'acme-2026' })
    expect(report.ok).toBe(true)
    const exportFile = report.files.find((f) => !/s-[12]\.jsonl$/.test(f.path))
    expect(exportFile).toBeDefined()
    const recs = (await readFile(join(dir, exportFile?.path ?? ''), 'utf8'))
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => JSON.parse(l))
    expect(recs).toHaveLength(1)
    expect(recs[0]).toMatchObject({
      kind: 'audit.export',
      caseId: 'acme-2026',
      data: { manifestSha256 },
    })
  })
})

describe('tar', () => {
  const entries = [
    { path: 'a.txt', data: Buffer.from('hello\n') },
    { path: `deep/${'d'.repeat(90)}/${'f'.repeat(60)}.jsonl`, data: Buffer.alloc(1000, 0x61) },
    { path: 'empty', data: new Uint8Array() },
  ]

  it('round-trips, including paths longer than 100 bytes', async () => {
    const out = await readTarGz(await writeTarGz(entries, now()))
    expect(out.map((e) => e.path)).toEqual(entries.map((e) => e.path))
    out.forEach((e, i) => {
      expect(Buffer.from(e.data).equals(Buffer.from(entries[i]?.data ?? []))).toBe(true)
    })
  })

  it('is deterministic: fixed mode 0644, uid/gid 0 and the given mtime', async () => {
    const a = await writeTarGz(entries, now())
    const b = await writeTarGz(entries, now())
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true)
    const tar = gunzipSync(a)
    const header = tar.subarray(0, 512)
    const field = (off: number, len: number) => header.subarray(off, off + len).toString('latin1')
    expect(field(100, 7)).toBe('0000644')
    expect(field(108, 7)).toBe('0000000')
    expect(field(116, 7)).toBe('0000000')
    expect(Number.parseInt(field(136, 11), 8)).toBe(Math.floor(now().getTime() / 1000))
    expect(field(257, 6)).toBe('ustar\0')
    expect(tar.byteLength % 512).toBe(0)
  })

  it('rejects unsafe paths and corrupt archives', async () => {
    await expect(writeTarGz([{ path: '../x', data: new Uint8Array() }], now())).rejects.toThrow()
    await expect(writeTarGz([{ path: '/abs', data: new Uint8Array() }], now())).rejects.toThrow()
    const good = gunzipSync(await writeTarGz(entries, now()))
    good[0] = good[0] === 0x61 ? 0x62 : 0x61 // break the header checksum
    const { gzipSync } = await import('node:zlib')
    await expect(readTarGz(gzipSync(good))).rejects.toThrow(/checksum/i)
  })
})

describe('size caps (fix round 1)', () => {
  const zeros = () => gzipSync(Buffer.alloc(1024 * 1024)) // ~1 KiB of gzip, 1 MiB inflated

  it('readTarGz stops at maxBytes instead of inflating everything', async () => {
    await expect(readTarGz(zeros(), { maxBytes: 64 * 1024 })).rejects.toBeInstanceOf(
      TarTooLargeError,
    )
  })

  it('verifyAuditBundle reports an over-cap bundle as BUNDLE_TOO_LARGE without throwing', async () => {
    const bomb = join(root, 'bomb.tar.gz')
    await writeFile(bomb, zeros())
    const report = await verifyAuditBundle(bomb, { maxBytes: 64 * 1024 })
    expect(report).toMatchObject({ ok: false, signatureValid: false })
    expect(report.files[0]?.errors[0]?.code).toBe('BUNDLE_TOO_LARGE')
  })

  it('checks the compressed size before reading the file', async () => {
    const big = join(root, 'big.tar.gz')
    await writeFile(big, Buffer.alloc(4096, 1))
    const report = await verifyAuditBundle(big, { maxBytes: 1024 })
    expect(report.files[0]?.errors[0]?.code).toBe('BUNDLE_TOO_LARGE')
  })

  it('a normal bundle passes under the default cap', async () => {
    const { path } = await doExport()
    expect((await verifyAuditBundle(path)).ok).toBe(true)
  })
})

describe('export robustness (fix round 1)', () => {
  it('exports despite a torn trailing index line (warning, not an error)', async () => {
    await appendFile(join(dir, 'index.jsonl'), '{"caseId":"acme-2026","sess')
    const { path } = await doExport()
    expect((await verifyAuditBundle(path)).ok).toBe(true)
  })

  it.skipIf(process.platform === 'win32')(
    'tightens loose permissions on an existing key dir and key file',
    async () => {
      await doExport(join(root, 'out', 'a.tar.gz'))
      const keysDir = join(home, 'keys')
      const keyPath = join(keysDir, 'audit-ed25519.pem')
      await chmod(keysDir, 0o755)
      await chmod(keyPath, 0o644)
      await doExport(join(root, 'out', 'b.tar.gz'))
      expect((await stat(keysDir)).mode & 0o777).toBe(0o700)
      expect((await stat(keyPath)).mode & 0o777).toBe(0o600)
    },
  )
})
