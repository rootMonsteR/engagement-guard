import { describe, expect, it } from 'vitest'
import {
  AUDIT_KINDS,
  type AuditRecord,
  AuditRecordSchema,
  genesisHash,
  hashRecord,
} from '../../src/audit/record.js'
import { sha256Hex } from '../../src/canonical.js'
import { REASON_CODES, TierSchema } from '../../src/policy/decisions.js'

function unhashed(): Omit<AuditRecord, 'hash'> {
  return {
    v: 1,
    seq: 0,
    ts: '2026-10-21T08:00:00.000Z',
    mono: 1234.5,
    operator: 'alice',
    caseId: 'acme-2026',
    sessionId: 's-1',
    kind: 'decision',
    callId: 'c-1',
    parentCallId: null,
    tool: 'Bash',
    command: 'nmap -sV 192.0.2.10',
    targets: [{ raw: '192.0.2.10', class: 'in', rule: '192.0.2.0/24', resolved: ['192.0.2.10'] }],
    scope: { verdict: 'pass', reason: 'IN_SCOPE', tier: 'vuln-scan' },
    permission: null,
    exec: null,
    data: null,
    prevHash: genesisHash('acme-2026', 's-1'),
  }
}

function hashed(): AuditRecord {
  const rest = unhashed()
  return { ...rest, hash: hashRecord(rest) }
}

function reversedKeys<T extends object>(o: T): T {
  return Object.fromEntries(Object.entries(o).reverse()) as T
}

describe('genesisHash', () => {
  it('is sha256 of the versioned case:session label', () => {
    expect(genesisHash('a', 'b')).toBe(sha256Hex('guard-audit-v1:a:b'))
    expect(genesisHash('a', 'b')).toMatch(/^[0-9a-f]{64}$/)
  })

  it('differs per session and per case', () => {
    expect(genesisHash('a', 'b')).not.toBe(genesisHash('a', 'c'))
    expect(genesisHash('a', 'b')).not.toBe(genesisHash('c', 'b'))
  })
})

describe('hashRecord', () => {
  it('is a 64-hex sha256 of the canonical record', () => {
    expect(hashRecord(unhashed())).toMatch(/^[0-9a-f]{64}$/)
  })

  it('is stable under key reordering', () => {
    const rec = unhashed()
    const reordered = reversedKeys(rec)
    reordered.targets = rec.targets.map(reversedKeys)
    expect(Object.keys(reordered)[0]).toBe('prevHash')
    expect(hashRecord(reordered)).toBe(hashRecord(rec))
  })

  it('ignores a hash field if one is passed', () => {
    const full = hashed()
    expect(hashRecord(full)).toBe(full.hash)
  })

  it('detects a record whose hash does not match its contents', () => {
    const tampered: AuditRecord = { ...hashed(), command: 'nmap -sV 198.51.100.7' }
    const { hash, ...rest } = tampered
    expect(hashRecord(rest)).not.toBe(hash)
    const intact = hashed()
    const { hash: intactHash, ...intactRest } = intact
    expect(hashRecord(intactRest)).toBe(intactHash)
  })

  it('changes when prevHash changes (chaining)', () => {
    const rec = unhashed()
    expect(hashRecord({ ...rec, prevHash: 'f'.repeat(64) })).not.toBe(hashRecord(rec))
  })
})

describe('AuditRecordSchema', () => {
  it('accepts a full decision record', () => {
    expect(AuditRecordSchema.parse(hashed())).toEqual(hashed())
  })

  it('accepts an exec.exit record with stdout/stderr digests', () => {
    const rec: AuditRecord = {
      ...hashed(),
      kind: 'exec.exit',
      scope: null,
      permission: { kind: 'allow', source: 'session', reason: null },
      exec: {
        backend: 'local',
        exitCode: 0,
        durationMs: 812,
        timedOut: false,
        stdout: { sha256: 'b'.repeat(64), bytes: 120 },
        stderr: null,
        artifactDir: '.guard/artifacts/r-1',
      },
      data: { note: 'x' },
    }
    expect(AuditRecordSchema.safeParse(rec).success).toBe(true)
  })

  it.each([
    ['an unknown top-level key', { extra: 1 }],
    ['v other than 1', { v: 2 }],
    ['a negative seq', { seq: -1 }],
    ['a fractional seq', { seq: 1.5 }],
    ['an unknown kind', { kind: 'session.pause' }],
    ['a non-hex prevHash', { prevHash: 'X'.repeat(64) }],
    ['a short hash', { hash: 'a'.repeat(63) }],
    ['an unknown reason code', { scope: { verdict: 'deny', reason: 'NOPE', tier: null } }],
    ['an unknown verdict', { scope: { verdict: 'allow', reason: 'IN_SCOPE', tier: null } }],
    ['an unknown tier', { scope: { verdict: 'pass', reason: 'IN_SCOPE', tier: 'dos' } }],
  ])('rejects %s', (_label, patch) => {
    expect(AuditRecordSchema.safeParse({ ...hashed(), ...patch }).success).toBe(false)
  })

  it('requires every nullable field to be present', () => {
    const { parentCallId: _p, ...rest } = hashed()
    expect(AuditRecordSchema.safeParse(rest).success).toBe(false)
  })
})

describe('AUDIT_KINDS', () => {
  it('lists the §6.6 record kinds', () => {
    expect(AUDIT_KINDS).toEqual([
      'session.start',
      'session.end',
      'decision',
      'answer',
      'permission',
      'tool.call',
      'exec.spawn',
      'exec.exit',
      'tool.result',
      'case.activate',
      'case.freeze',
      'case.edit',
      'ack.first-run',
      'audit.export',
      'audit.degraded',
    ])
  })
})

describe('policy enums', () => {
  it('REASON_CODES is exactly Appendix B, in order (plus PROTECTED_PATH, ruling P24)', () => {
    expect(REASON_CODES).toMatchInlineSnapshot(`
      [
        "HARD_REFUSAL",
        "PROTECTED_PATH",
        "FIRST_RUN_REQUIRED",
        "NO_ACTIVE_CASE",
        "CASE_INVALID",
        "NOT_ACKNOWLEDGED",
        "SCOPE_TAMPERED",
        "OUTSIDE_WINDOW",
        "BLACKOUT",
        "OUT_OF_SCOPE",
        "RESOLVES_OUT_OF_SCOPE",
        "RESOLVES_PRIVATE",
        "INFRA_NOT_TARGET",
        "TIER_NOT_AUTHORISED",
        "RATE_EXCEEDS_ROE",
        "AUDIT_UNAVAILABLE",
        "GUARD_ERROR",
        "EXPLOITATION_CONFIRM",
        "UNKNOWN_TARGET",
        "UNRESOLVABLE",
        "THIRD_PARTY_HOSTING",
        "RANGE_NOT_FULLY_AUTHORISED",
        "NO_TARGETS_FOUND",
        "OPAQUE_CONSTRUCT",
        "INTERPRETER_TARGETS",
        "POWERSHELL_NETWORK_TOOL",
        "IN_SCOPE",
        "OPERATOR_INFRA",
        "TRUSTED_INFRA",
        "LOCAL_TARGET",
        "NOT_NETWORK",
      ]
    `)
  })

  it('TierSchema lists the RoE tiers', () => {
    expect(TierSchema.options).toEqual([
      'recon',
      'vuln-scan',
      'exploitation',
      'post-exploitation',
      'bruteforce',
    ])
  })
})
