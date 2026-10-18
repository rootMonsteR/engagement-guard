import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { parse } from 'yaml'
import { REDACTED, redact, redactDeep } from '../../src/audit/redact.js'
import { verifyAudit } from '../../src/audit/verify.js'
import { createAuditLog } from '../../src/audit/writer.js'

interface CorpusRow {
  family: string
  input: string
  mustNotContain?: string[]
  mustContain?: string[]
  unchanged?: boolean
}

const corpus = parse(
  await readFile(new URL('../fixtures/redaction-corpus.yaml', import.meta.url), 'utf8'),
) as CorpusRow[]

describe('redaction corpus', () => {
  it('has at least 25 rows, and every family has a positive row and a near-miss row', () => {
    expect(corpus.length).toBeGreaterThanOrEqual(25)
    const families = new Map<string, { positive: number; nearMiss: number }>()
    for (const row of corpus) {
      const f = families.get(row.family) ?? { positive: 0, nearMiss: 0 }
      if (row.unchanged) f.nearMiss++
      else f.positive++
      families.set(row.family, f)
    }
    for (const [family, counts] of families) {
      expect(counts.positive, `${family} positive rows`).toBeGreaterThan(0)
      expect(counts.nearMiss, `${family} near-miss rows`).toBeGreaterThan(0)
    }
    for (const family of [
      'url-userinfo',
      'user-flag',
      'password-flag',
      'header',
      'bearer',
      'kv',
      'aws',
      'github',
      'anthropic',
      'openai',
      'slack',
      'jwt',
      'private-key',
      'ntlm',
    ]) {
      expect(families.has(family), family).toBe(true)
    }
  })

  it.each(corpus.map((row) => [row.family, row.input, row] as const))(
    '%s: %s',
    (_family, input, row) => {
      const out = redact(input)
      if (row.unchanged) {
        expect(out).toBe(input)
        return
      }
      expect(row.mustNotContain?.length ?? 0).toBeGreaterThan(0)
      expect(out).toContain(REDACTED)
      for (const secret of row.mustNotContain ?? []) expect(out).not.toContain(secret)
      for (const kept of row.mustContain ?? []) expect(out).toContain(kept)
    },
  )

  it('stays fast on long adversarial input (no quadratic backtracking)', () => {
    for (const unit of ['a.', 'a-', 'sk-', 'h://', 'a:', 'a@', '/a', 'token=']) {
      const input = unit.repeat(40_000)
      const started = performance.now()
      redact(input)
      expect(performance.now() - started, unit).toBeLessThan(1500)
    }
  })

  it('is idempotent on every row', () => {
    for (const row of corpus) {
      const once = redact(row.input)
      expect(redact(once), row.input).toBe(once)
    }
  })
})

describe('redactDeep', () => {
  it('redacts every string leaf without mutating the input', () => {
    const input = {
      cmd: 'curl -u admin:S3cr3t! https://acme.example',
      nested: { list: ['ok', 'Bearer AbC123xyz987TOKEN', 7, true, null] },
      n: 42,
    }
    const snapshot = structuredClone(input)
    const out = redactDeep(input)
    expect(input).toEqual(snapshot)
    expect(JSON.stringify(out)).not.toContain('S3cr3t!')
    expect(JSON.stringify(out)).not.toContain('AbC123xyz987TOKEN')
    expect(out.nested.list[0]).toBe('ok')
    expect(out.nested.list.slice(2)).toEqual([7, true, null])
    expect(out.n).toBe(42)
  })

  it('redacts string values under credential-named keys', () => {
    const out = redactDeep({
      password: 'hunter2',
      apiKey: 'plain',
      client_secret: 'x',
      maxTokens: 'keep',
      tokenizer: 'keep',
      summary: 'keep',
    })
    expect(out).toEqual({
      password: REDACTED,
      apiKey: REDACTED,
      client_secret: REDACTED,
      maxTokens: 'keep',
      tokenizer: 'keep',
      summary: 'keep',
    })
  })

  it('treats string arrays as argv, where a secret is the element after its flag', () => {
    expect(redactDeep(['nxc', 'smb', '192.0.2.10', '-u', 'admin', '-p', 'Winter2026!'])).toEqual([
      'nxc',
      'smb',
      '192.0.2.10',
      '-u',
      'admin',
      '-p',
      REDACTED,
    ])
    expect(redactDeep(['curl', '-u', 'admin:pw', 'https://acme.example'])).toEqual([
      'curl',
      '-u',
      `admin:${REDACTED}`,
      'https://acme.example',
    ])
    expect(redactDeep(['tool', '--password', 'TopSecret', '--api-key', 'k'])).toEqual([
      'tool',
      '--password',
      REDACTED,
      '--api-key',
      REDACTED,
    ])
    expect(redactDeep(['nxc', 'smb', 'h', '-H', '31d6cfe0d16ae931b73c59d7e0c089c0'])).toContain(
      REDACTED,
    )
    const benign = ['nmap', '-p', '80,443', '192.0.2.10']
    expect(redactDeep(benign)).toEqual(benign)
    const header = ['curl', '-H', 'Accept: application/json', 'https://acme.example']
    expect(redactDeep(header)).toEqual(header)
  })

  it('returns primitives as they are and redacts a bare string', () => {
    expect(redactDeep(5)).toBe(5)
    expect(redactDeep(null)).toBe(null)
    expect(redactDeep('token=abc123')).toBe(`token=${REDACTED}`)
  })
})

describe('redaction before hashing', () => {
  let dir: string | undefined
  afterEach(async () => {
    if (dir) await rm(dir, { recursive: true, force: true })
    dir = undefined
  })

  it('never writes the secret of a decision command to disk, and the chain still verifies', async () => {
    dir = await mkdtemp(join(tmpdir(), 'guard-redact-'))
    const audit = createAuditLog({ dir, sessionId: 's-1', operator: 'alice' })
    audit.setCase('acme-2026')
    const rec = await audit.append({
      kind: 'decision',
      callId: 'toolu_1',
      tool: 'Bash',
      command: 'curl -u admin:S3cr3t! https://acme.example',
      targets: [
        {
          raw: 'https://admin:S3cr3t!@acme.example',
          class: 'in',
          rule: 'acme.example',
          resolved: ['192.0.2.10'],
        },
      ],
      scope: { verdict: 'pass', reason: 'IN_SCOPE', tier: 'recon' },
      data: {
        note: 'password=S3cr3t!',
        deep: [{ header: 'Authorization: Basic YWRtaW46UzNjcjN0IQ==' }],
      },
    })
    expect(rec.command).toBe(`curl -u admin:${REDACTED} https://acme.example`)
    const caseDir = join(dir, 'acme-2026')
    const [file] = await readdir(caseDir)
    const bytes = await readFile(join(caseDir, file as string), 'utf8')
    expect(bytes).not.toContain('S3cr3t!')
    expect(bytes).not.toContain('YWRtaW46UzNjcjN0IQ==')
    const report = await verifyAudit(dir)
    expect(report.ok).toBe(true)
    expect(report.files[0]?.records).toBe(1)
  })
})

describe('redactDeep argv keeps the command context (fix round 1)', () => {
  it.each([
    [['mysql', '-uroot', '-pTopSecret'], 'TopSecret', ['mysql', '-uroot', '-p']],
    [['sshpass', '-pHunter2', 'ssh', 'h'], 'Hunter2', ['sshpass', 'ssh', 'h']],
    [
      ['nxc', 'smb', 'h', '-u', 'a', '-pWinter2026!'],
      'Winter2026!',
      ['nxc', 'smb', 'h', '-u', 'a'],
    ],
    [
      ['impacket-psexec', 'ACME/admin:Passw0rd!@192.0.2.10'],
      'Passw0rd!',
      ['impacket-psexec', 'ACME/admin:', '@192.0.2.10'],
    ],
  ])('%j', (argv, secret, kept) => {
    const out = redactDeep(argv)
    expect(JSON.stringify(out)).not.toContain(secret)
    expect(out).toHaveLength(argv.length)
    for (const k of kept)
      expect(
        out.some((x) => x.includes(k)),
        k,
      ).toBe(true)
  })

  it('leaves an attached -p alone outside a credential context', () => {
    const argv = ['nmap', '-p80,443', '192.0.2.10']
    expect(redactDeep(argv)).toEqual(argv)
  })
})
