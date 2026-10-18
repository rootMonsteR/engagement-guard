import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  randomBytes,
  sign,
  verify,
} from 'node:crypto'
import { chmod, mkdir, readFile, stat, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { z } from 'zod'
import { sha256Hex } from '../canonical.js'
import { verifyChain } from './chain.js'
import { INDEX_FILE, IndexEntrySchema, type VerifyError } from './layout.js'
import { readTarGz, type TarEntry, TarTooLargeError, writeTarGz } from './tar.js'
import { isCode, messageOf } from './util.js'
import {
  type AuditSource,
  type VerifyFileReport,
  type VerifyReport,
  verifyAudit,
  verifySource,
} from './verify.js'
import { type AuditLog, createAuditLog } from './writer.js'

/** Default cap on a bundle's size, compressed and inflated (256 MiB). */
export const DEFAULT_MAX_BUNDLE_BYTES = 256 * 1024 * 1024

const MANIFEST = 'manifest.json'
const SIGNATURE = 'manifest.sig'
const PUBLIC_KEY = 'audit-public-key.pem'
const AUDIT_PREFIX = 'audit/'
const META_FILES = new Set([MANIFEST, SIGNATURE, PUBLIC_KEY])

/** Where the audit signing key lives under `GuardPaths.home` (`<home>/keys/audit-ed25519.pem`). */
export const AUDIT_KEY_FILE = join('keys', 'audit-ed25519.pem')

const ManifestFileSchema = z.object({
  path: z.string(),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  bytes: z.number().int().nonnegative(),
  records: z.number().int().nonnegative(),
  head: z.string().nullable(),
})

/** `manifest.json` of an export bundle; `manifest.sig` is ed25519 over its exact bytes. */
export const AuditManifestSchema = z.object({
  caseId: z.string(),
  createdAt: z.string(),
  operator: z.string(),
  files: z.array(ManifestFileSchema),
  verify: z.object({ ok: z.boolean(), files: z.array(z.unknown()) }),
})
export type AuditManifest = z.infer<typeof AuditManifestSchema>

/** On POSIX, narrows the keys directory to 0700 and the key file to 0600 when they are looser. */
async function tightenKeyPermissions(path: string): Promise<void> {
  if (process.platform === 'win32') return
  for (const [p, mode] of [
    [dirname(path), 0o700],
    [path, 0o600],
  ] as const) {
    if (((await stat(p)).mode & 0o777 & ~mode) !== 0) await chmod(p, mode)
  }
}

/**
 * Loads the ed25519 signing key, creating it (mode 0600, directory 0700) on first use; an
 * existing key whose file or directory is looser than that is tightened on load.
 */
async function signingKey(home: string): Promise<KeyObject> {
  const path = join(home, AUDIT_KEY_FILE)
  const load = async (): Promise<KeyObject> => {
    const key = createPrivateKey(await readFile(path, 'utf8'))
    if (key.asymmetricKeyType !== 'ed25519')
      throw new Error(`${path} is not an ed25519 private key`)
    await tightenKeyPermissions(path)
    return key
  }
  try {
    return await load()
  } catch (err) {
    if (!isCode(err, 'ENOENT')) throw err
  }
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  const { privateKey } = generateKeyPairSync('ed25519')
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
  try {
    await writeFile(path, pem, { mode: 0o600, flag: 'wx' })
  } catch (err) {
    if (isCode(err, 'EEXIST')) return load() // created concurrently
    throw err
  }
  return privateKey
}

const compactStamp = (d: Date): string =>
  d
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.\d+Z$/, 'Z')

function describeErrors(report: VerifyReport): string {
  const errs = report.files.flatMap((f) =>
    f.errors.map((e) => `${f.path}: ${e.code}${e.seq === null ? '' : ` (seq ${e.seq})`}`),
  )
  return errs.slice(0, 5).join('; ') + (errs.length > 5 ? `; … ${errs.length - 5} more` : '')
}

/**
 * Exports one case's audit chains as a signed, deterministic `.tar.gz` bundle: `manifest.json`
 * (file digests, record counts, heads and the verify report), `manifest.sig`, the public key,
 * the case's `index.jsonl` lines and `audit/<caseId>/*.jsonl`. Refuses when the case's log does
 * not verify, has no records, or `out` already exists. Afterwards an `audit.export` record is
 * written: to `audit` when given and on this case, otherwise to a chain of its own.
 */
export async function exportAudit(opts: {
  dir: string
  caseId: string
  /** The bundle path, or an existing directory to put `<caseId>-audit-<stamp>.tar.gz` in. */
  out: string
  /** `GuardPaths.home`; the signing key is `<home>/keys/audit-ed25519.pem`. */
  home: string
  operator: string
  now?: () => Date
  /** The live session log, used for the `audit.export` record when it is on this case. */
  audit?: AuditLog
}): Promise<{ path: string; manifestSha256: string }> {
  const { dir, caseId, operator } = opts
  const createdAt = (opts.now ?? (() => new Date()))()

  const gate = await verifyAudit(dir, { caseId })
  if (!gate.ok) {
    throw new Error(
      `refusing to export case ${caseId}: its audit log does not verify (${describeErrors(gate)})`,
    )
  }
  // A warning-only index report (torn index tail) is not a chain to bundle.
  const gateChains = gate.files.filter((f) => f.path !== INDEX_FILE)
  if (gateChains.length === 0) throw new Error(`no audit records for case ${caseId}`)

  // The index lines of exactly the verified files, byte-for-byte (a chain started since the
  // check is neither bundled nor indexed).
  const verified = new Set(gateChains.map((f) => f.path))
  const indexLines = (await readFile(join(dir, INDEX_FILE), 'utf8')).split('\n').filter((line) => {
    if (line === '') return false
    try {
      const entry = IndexEntrySchema.safeParse(JSON.parse(line))
      return entry.success && entry.data.caseId === caseId && verified.has(entry.data.file)
    } catch {
      return false
    }
  })
  const indexBytes = Buffer.from(indexLines.map((l) => `${l}\n`).join(''), 'utf8')

  // Manifest and bundle describe exactly the bytes read here (re-verified, in case of a writer).
  const chains: TarEntry[] = []
  const files: AuditManifest['files'] = [
    {
      path: INDEX_FILE,
      sha256: sha256Hex(indexBytes),
      bytes: indexBytes.byteLength,
      records: indexLines.length,
      head: null,
    },
  ]
  const reports: VerifyFileReport[] = []
  for (const f of gateChains) {
    const bytes = await readFile(join(dir, ...f.path.split('/')))
    const check = verifyChain(bytes.toString('utf8'), f.caseId, f.sessionId)
    if (check.errors.length > 0) {
      throw new Error(
        `refusing to export case ${caseId}: ${f.path} changed while exporting and does not verify`,
      )
    }
    const path = `${AUDIT_PREFIX}${f.path}`
    chains.push({ path, data: bytes })
    files.push({
      path,
      sha256: sha256Hex(bytes),
      bytes: bytes.byteLength,
      records: check.records,
      head: check.head,
    })
    reports.push({ ...f, records: check.records, head: check.head, errors: [] })
  }

  const manifest: AuditManifest = {
    caseId,
    createdAt: createdAt.toISOString(),
    operator,
    files,
    verify: { ok: true, files: reports },
  }
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  const manifestSha256 = sha256Hex(manifestBytes)
  const key = await signingKey(opts.home)
  const signature = sign(null, manifestBytes, key).toString('base64')
  const publicPem = createPublicKey(key).export({ type: 'spki', format: 'pem' }) as string

  const archive = await writeTarGz(
    [
      { path: MANIFEST, data: manifestBytes },
      { path: SIGNATURE, data: Buffer.from(`${signature}\n`, 'utf8') },
      { path: PUBLIC_KEY, data: Buffer.from(publicPem, 'utf8') },
      { path: INDEX_FILE, data: indexBytes },
      ...chains,
    ],
    createdAt,
  )

  let path = opts.out
  const outStat = await stat(path).catch(() => undefined)
  if (outStat?.isDirectory()) path = join(path, `${caseId}-audit-${compactStamp(createdAt)}.tar.gz`)
  await mkdir(dirname(path), { recursive: true })
  try {
    await writeFile(path, archive, { flag: 'wx' })
  } catch (err) {
    if (isCode(err, 'EEXIST'))
      throw new Error(`${path} already exists; refusing to overwrite an audit bundle`)
    throw err
  }

  const record = {
    kind: 'audit.export' as const,
    data: {
      out: path,
      manifestSha256,
      files: chains.length,
      publicKeySha256: sha256Hex(publicPem),
    },
  }
  let log = opts.audit
  if (log === undefined || log.caseId !== caseId) {
    log = createAuditLog({
      dir,
      sessionId: `export-${compactStamp(createdAt)}-${randomBytes(3).toString('hex')}`,
      operator,
      ...(opts.now ? { now: opts.now } : {}),
    })
    log.setCase(caseId)
  }
  try {
    await log.append(record, { sync: true })
  } catch (err) {
    throw new Error(
      `bundle written to ${path}, but its audit.export record failed: ${messageOf(err)}`,
    )
  }
  return { path, manifestSha256 }
}

function bundleSource(entries: Map<string, Uint8Array>): AuditSource {
  return {
    async readIndex() {
      const data = entries.get(INDEX_FILE)
      return data === undefined ? null : Buffer.from(data).toString('utf8')
    },
    async read(file) {
      return entries.get(`${AUDIT_PREFIX}${file}`) ?? null
    },
    async listJsonl(caseId) {
      return [...entries.keys()]
        .filter((p) => p.startsWith(AUDIT_PREFIX) && p.endsWith('.jsonl'))
        .map((p) => p.slice(AUDIT_PREFIX.length))
        .filter((p) => caseId === undefined || p.startsWith(`${caseId}/`))
        .sort()
    },
  }
}

const fileError = (code: VerifyError['code'], message: string): VerifyError => ({
  seq: null,
  line: 0,
  code,
  message,
})

/**
 * Verifies an export bundle: the manifest signature (against the public key in the bundle — pin
 * `publicKeySha256` to trust it), every manifest digest, no unlisted files, and each bundled
 * chain. Never throws: an unreadable bundle is a `PARSE_ERROR`, and one whose file or inflated
 * content exceeds `maxBytes` (default 256 MiB) is `BUNDLE_TOO_LARGE`, found before it is read or
 * inflated past the cap.
 */
export async function verifyAuditBundle(
  path: string,
  opts: { maxBytes?: number } = {},
): Promise<VerifyReport & { signatureValid: boolean; publicKeySha256: string | null }> {
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BUNDLE_BYTES
  const unreadable = (code: VerifyError['code'], message: string) => ({
    ok: false,
    signatureValid: false,
    publicKeySha256: null,
    files: [
      {
        path,
        caseId: '',
        sessionId: '',
        records: 0,
        head: null,
        errors: [fileError(code, message)],
      },
    ],
  })
  let list: TarEntry[]
  try {
    const size = (await stat(path)).size
    if (size > maxBytes) {
      return unreadable(
        'BUNDLE_TOO_LARGE',
        `bundle is ${size} bytes, over the ${maxBytes}-byte cap`,
      )
    }
    list = await readTarGz(await readFile(path), { maxBytes })
  } catch (err) {
    if (err instanceof TarTooLargeError) return unreadable('BUNDLE_TOO_LARGE', err.message)
    return unreadable('PARSE_ERROR', `cannot read bundle: ${messageOf(err)}`)
  }
  const entries = new Map<string, Uint8Array>()
  const reports: VerifyFileReport[] = []
  const reportFor = (p: string): VerifyFileReport => {
    let r = reports.find((x) => x.path === p)
    if (r === undefined) {
      r = { path: p, caseId: '', sessionId: '', records: 0, head: null, errors: [] }
      reports.push(r)
    }
    return r
  }
  for (const e of list) {
    if (entries.has(e.path))
      reportFor(e.path).errors.push(fileError('SCHEMA', 'duplicate entry in bundle'))
    entries.set(e.path, e.data)
  }
  const manifestBytes = entries.get(MANIFEST)
  const signatureBytes = entries.get(SIGNATURE)
  const publicBytes = entries.get(PUBLIC_KEY)
  if (manifestBytes === undefined || signatureBytes === undefined || publicBytes === undefined) {
    return unreadable(
      'PARSE_ERROR',
      `bundle lacks ${[MANIFEST, SIGNATURE, PUBLIC_KEY].filter((p) => !entries.has(p)).join(', ')}`,
    )
  }

  let signatureValid = false
  const publicKeySha256 = sha256Hex(publicBytes)
  try {
    const publicKey = createPublicKey(Buffer.from(publicBytes).toString('utf8'))
    const signature = Buffer.from(Buffer.from(signatureBytes).toString('utf8').trim(), 'base64')
    signatureValid =
      publicKey.asymmetricKeyType === 'ed25519' && verify(null, manifestBytes, publicKey, signature)
  } catch {
    signatureValid = false
  }

  let manifest: AuditManifest
  try {
    const parsed = AuditManifestSchema.safeParse(
      JSON.parse(Buffer.from(manifestBytes).toString('utf8')),
    )
    if (!parsed.success) {
      reportFor(MANIFEST).errors.push(
        fileError('SCHEMA', parsed.error.issues.map((i) => i.message).join('; ')),
      )
      return { ok: false, signatureValid, publicKeySha256, files: reports }
    }
    manifest = parsed.data
  } catch (err) {
    reportFor(MANIFEST).errors.push(fileError('PARSE_ERROR', messageOf(err)))
    return { ok: false, signatureValid, publicKeySha256, files: reports }
  }

  const chainReport = await verifySource(bundleSource(entries), {
    caseId: manifest.caseId,
    displayPrefix: AUDIT_PREFIX,
  })
  // verifySource prefixes the index path too; in a bundle it sits at the root.
  for (const r of chainReport.files) {
    const p = r.path === `${AUDIT_PREFIX}${INDEX_FILE}` ? INDEX_FILE : r.path
    const target = reportFor(p)
    Object.assign(target, { ...r, path: p, errors: [...target.errors, ...r.errors] })
  }

  const listed = new Set(manifest.files.map((f) => f.path))
  for (const f of manifest.files) {
    const data = entries.get(f.path)
    const r = reportFor(f.path)
    if (data === undefined) {
      if (!r.errors.some((e) => e.code === 'MISSING_FILE')) {
        r.errors.push(fileError('MISSING_FILE', 'listed in the manifest but not in the bundle'))
      }
      continue
    }
    if (sha256Hex(data) !== f.sha256 || data.byteLength !== f.bytes) {
      r.errors.push(fileError('HASH_MISMATCH', 'sha256 does not match the manifest'))
    } else if (f.path !== INDEX_FILE && (r.head !== f.head || r.records !== f.records)) {
      r.errors.push(fileError('SCHEMA', 'record count or head differs from the manifest'))
    }
  }
  for (const p of entries.keys()) {
    if (!META_FILES.has(p) && !listed.has(p)) {
      reportFor(p).errors.push(fileError('UNINDEXED_FILE', 'in the bundle but not in the manifest'))
    }
  }

  // Only reports about real chain files, or with errors, are returned.
  const files = reports.filter(
    (r) => r.errors.length > 0 || (r.path.startsWith(AUDIT_PREFIX) && r.sessionId !== ''),
  )
  return {
    ok: signatureValid && files.every((r) => r.errors.length === 0),
    signatureValid,
    publicKeySha256,
    files,
  }
}
