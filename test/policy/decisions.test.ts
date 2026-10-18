import { describe, expect, it } from 'vitest'
import {
  askPrompt,
  formatDecision,
  type GuardAnnotation,
  type GuardTarget,
  REASON_CODES,
  type ReasonCode,
} from '../../src/policy/decisions.js'

const CTX = { casePath: '.guard/engagement.yaml' }
const AUTHORISE =
  'If the client has authorised this, the operator can update `.guard/engagement.yaml` and run `engagement-guard engagement edit` (audited). Do not try to work around this check.'

const t = (
  raw: string,
  cls: GuardTarget['class'],
  rule: string | null = null,
  resolved: string[] = [],
) => ({ raw, class: cls, rule, resolved }) satisfies GuardTarget

const base = (over: Partial<GuardAnnotation> & Pick<GuardAnnotation, 'verdict' | 'reason'>) =>
  ({
    caseId: 'acme-ext-2026',
    tier: 'recon',
    targets: [],
    opaque: [],
    suggestion: null,
    ...over,
  }) satisfies GuardAnnotation

/** One representative annotation per Appendix B reason code. */
const FIXTURES: Record<ReasonCode, GuardAnnotation> = {
  HARD_REFUSAL: base({
    verdict: 'deny',
    reason: 'HARD_REFUSAL',
    tier: null,
    targets: [t('192.0.2.10', 'in-scope', 'in[0]: 192.0.2.0/24')],
    denyEntry: {
      id: 'nmap-script-dos',
      description: 'nmap --script selecting DoS scripts or categories that include them',
    },
    suggestion: '--script "vuln and not dos"',
  }),
  PROTECTED_PATH: base({
    verdict: 'deny',
    reason: 'PROTECTED_PATH',
    tier: null,
    rule: '/work/.guard/engagement.yaml',
    detail: 'Write /work/.guard/engagement.yaml',
  }),
  FIRST_RUN_REQUIRED: base({
    verdict: 'deny',
    reason: 'FIRST_RUN_REQUIRED',
    caseId: null,
    targets: [t('192.0.2.10', 'no-engagement')],
  }),
  NO_ACTIVE_CASE: base({
    verdict: 'deny',
    reason: 'NO_ACTIVE_CASE',
    caseId: null,
    targets: [t('scanme.acme.example', 'no-engagement')],
  }),
  CASE_INVALID: base({
    verdict: 'deny',
    reason: 'CASE_INVALID',
    caseId: null,
    targets: [t('192.0.2.10', 'no-engagement')],
    detail: 'scope.in[1]: expected an IP, range, hostname or URL',
  }),
  NOT_ACKNOWLEDGED: base({
    verdict: 'deny',
    reason: 'NOT_ACKNOWLEDGED',
    targets: [t('192.0.2.10', 'not-acknowledged')],
  }),
  SCOPE_TAMPERED: base({
    verdict: 'deny',
    reason: 'SCOPE_TAMPERED',
    targets: [t('192.0.2.10', 'not-acknowledged')],
    rule: 'frozen scope_hash 3f2a…9c1d ≠ current 77be…0a42',
  }),
  OUTSIDE_WINDOW: base({
    verdict: 'deny',
    reason: 'OUTSIDE_WINDOW',
    targets: [t('192.0.2.10', 'outside-window')],
    rule: 'window: 2026-10-01T09:00:00+01:00 → 2026-10-12T18:00:00+01:00',
  }),
  BLACKOUT: base({
    verdict: 'deny',
    reason: 'BLACKOUT',
    targets: [t('192.0.2.10', 'blackout')],
    rule: 'roe.blackout_hours[0]: Mon–Fri 12:00–13:00 Europe/London',
  }),
  OUT_OF_SCOPE: base({
    verdict: 'deny',
    reason: 'OUT_OF_SCOPE',
    targets: [
      t('192.0.2.10', 'in-scope', 'in[0]: 192.0.2.0/24'),
      t('203.0.113.5', 'out-of-scope', 'out[0]: 203.0.113.0/24'),
    ],
  }),
  RESOLVES_OUT_OF_SCOPE: base({
    verdict: 'deny',
    reason: 'RESOLVES_OUT_OF_SCOPE',
    targets: [t('shop.acme.example', 'out-of-scope', 'out[1]: 198.51.100.0/24', ['198.51.100.20'])],
  }),
  RESOLVES_PRIVATE: base({
    verdict: 'deny',
    reason: 'RESOLVES_PRIVATE',
    targets: [t('intranet.acme.example', 'out-of-scope', 'in[2]: *.acme.example', ['10.20.0.5'])],
  }),
  INFRA_NOT_TARGET: base({
    verdict: 'deny',
    reason: 'INFRA_NOT_TARGET',
    tier: 'vuln-scan',
    targets: [
      {
        ...t('registry.npmjs.org', 'trusted-infra', 'trusted_infrastructure: registry.npmjs.org'),
        role: 'infra',
      },
    ],
  }),
  TIER_NOT_AUTHORISED: base({
    verdict: 'deny',
    reason: 'TIER_NOT_AUTHORISED',
    tier: 'exploitation',
    targets: [t('192.0.2.10', 'in-scope', 'in[0]: 192.0.2.0/24')],
    rule: 'roe.allowed_test_classes: recon, vuln-scan',
  }),
  RATE_EXCEEDS_ROE: base({
    verdict: 'deny',
    reason: 'RATE_EXCEEDS_ROE',
    targets: [t('192.0.2.0/28', 'in-scope', 'in[0]: 192.0.2.0/24')],
    rule: 'roe.rate_limits.nmap_max_timing: 3 (requested -T5)',
    suggestion: '-T3',
  }),
  AUDIT_UNAVAILABLE: base({
    verdict: 'deny',
    reason: 'AUDIT_UNAVAILABLE',
    targets: [t('192.0.2.10', 'in-scope', 'in[0]: 192.0.2.0/24')],
    detail: 'ENOSPC: no space left on device',
  }),
  GUARD_ERROR: base({
    verdict: 'deny',
    reason: 'GUARD_ERROR',
    tier: null,
    detail: 'TypeError: cannot read properties of undefined',
  }),
  EXPLOITATION_CONFIRM: base({
    verdict: 'ask-unskippable',
    reason: 'EXPLOITATION_CONFIRM',
    tier: 'exploitation',
    targets: [
      t('https://portal.acme.example/login', 'in-scope', 'in[3]: https://portal.acme.example/'),
    ],
  }),
  UNKNOWN_TARGET: base({
    verdict: 'ask',
    reason: 'UNKNOWN_TARGET',
    targets: [t('partner.acme-partner.example', 'unknown')],
  }),
  UNRESOLVABLE: base({
    verdict: 'ask',
    reason: 'UNRESOLVABLE',
    targets: [t('old.acme.example', 'in-scope', 'in[2]: *.acme.example')],
  }),
  THIRD_PARTY_HOSTING: base({
    verdict: 'ask',
    reason: 'THIRD_PARTY_HOSTING',
    targets: [t('www.acme.example', 'unknown', 'in[2]: *.acme.example', ['198.51.100.77'])],
  }),
  RANGE_NOT_FULLY_AUTHORISED: base({
    verdict: 'ask',
    reason: 'RANGE_NOT_FULLY_AUTHORISED',
    targets: [t('192.0.2.0/23', 'unknown', 'in[0]: 192.0.2.0/24')],
  }),
  NO_TARGETS_FOUND: base({ verdict: 'ask', reason: 'NO_TARGETS_FOUND' }),
  OPAQUE_CONSTRUCT: base({
    verdict: 'ask',
    reason: 'OPAQUE_CONSTRUCT',
    opaque: ['command-substitution', 'variable'],
  }),
  INTERPRETER_TARGETS: base({
    verdict: 'ask',
    reason: 'INTERPRETER_TARGETS',
    tier: null,
    targets: [t('192.0.2.10', 'in-scope', 'in[0]: 192.0.2.0/24')],
  }),
  POWERSHELL_NETWORK_TOOL: base({
    verdict: 'ask',
    reason: 'POWERSHELL_NETWORK_TOOL',
    tier: null,
    opaque: ['powershell'],
  }),
  IN_SCOPE: base({
    verdict: 'pass',
    reason: 'IN_SCOPE',
    targets: [t('192.0.2.10', 'in-scope', 'in[0]: 192.0.2.0/24')],
  }),
  OPERATOR_INFRA: base({
    verdict: 'pass',
    reason: 'OPERATOR_INFRA',
    targets: [
      {
        ...t('203.0.113.200', 'operator-infra', 'operator_infrastructure[0]: 203.0.113.200'),
        role: 'infra',
      },
    ],
  }),
  TRUSTED_INFRA: base({
    verdict: 'pass',
    reason: 'TRUSTED_INFRA',
    caseId: null,
    tier: 'recon',
    targets: [
      { ...t('github.com', 'trusted-infra', 'trusted_infrastructure: github.com'), role: 'infra' },
    ],
  }),
  LOCAL_TARGET: base({
    verdict: 'pass',
    reason: 'LOCAL_TARGET',
    caseId: null,
    targets: [t('127.0.0.1:8080', 'local')],
  }),
  NOT_NETWORK: base({ verdict: 'pass', reason: 'NOT_NETWORK', caseId: null, tier: null }),
}

describe('formatDecision', () => {
  it('has a fixture for every reason code', () => {
    expect(Object.keys(FIXTURES).sort()).toEqual([...REASON_CODES].sort())
  })

  for (const code of REASON_CODES) {
    it(`${code}: names its code, is plain, short and stable`, () => {
      const a = FIXTURES[code]
      const text = formatDecision(a, CTX)
      expect(text).toContain(code)
      expect(text.split('\n').length).toBeLessThanOrEqual(12)
      expect(text).not.toMatch(/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/)
      expect(formatDecision(structuredClone(a), CTX)).toBe(text)
      expect(text).toMatchSnapshot()
    })
  }

  it('every deny names its targets, their rules and the reason code', () => {
    for (const code of REASON_CODES) {
      const a = FIXTURES[code]
      if (a.verdict !== 'deny') continue
      const text = formatDecision(a, CTX)
      expect(text).toContain(code)
      for (const target of a.targets) {
        expect(text).toContain(target.raw)
        if (target.rule) expect(text).toContain(target.rule)
      }
      if (a.denyEntry) {
        expect(text).toContain(a.denyEntry.id)
        expect(text).toContain(a.denyEntry.description)
      } else if (a.rule) expect(text).toContain(a.rule)
      if (a.targets.length === 0) expect(text).toMatch(/Targets?: none/)
    }
  })

  it('OUT_OF_SCOPE and RESOLVES_* end with the authorisation sentence', () => {
    for (const code of ['OUT_OF_SCOPE', 'RESOLVES_OUT_OF_SCOPE', 'RESOLVES_PRIVATE'] as const) {
      expect(formatDecision(FIXTURES[code], CTX).endsWith(AUTHORISE)).toBe(true)
    }
  })

  it('RESOLVES_* show the resolved addresses', () => {
    expect(formatDecision(FIXTURES.RESOLVES_OUT_OF_SCOPE, CTX)).toContain('198.51.100.20')
    expect(formatDecision(FIXTURES.RESOLVES_PRIVATE, CTX)).toContain('10.20.0.5')
  })

  it('RATE_EXCEEDS_ROE includes the compliant suggestion', () => {
    expect(formatDecision(FIXTURES.RATE_EXCEEDS_ROE, CTX)).toContain('-T3')
  })

  it('NO_ACTIVE_CASE points to engagement-guard init', () => {
    expect(formatDecision(FIXTURES.NO_ACTIVE_CASE, CTX)).toContain('engagement-guard init')
  })

  it('names the case file and command hint it is given (GuardPaths)', () => {
    const hints = { engagementPath: '.case/engagement.yaml', commandHint: 'acme case edit' }
    const deny = formatDecision(FIXTURES.OUT_OF_SCOPE, { ...CTX, ...hints })
    expect(deny).toContain('update `.case/engagement.yaml` and run `acme case edit` (audited)')
    expect(askPrompt(FIXTURES.UNKNOWN_TARGET, 'curl x', hints).detail).toContain(
      'add it with `acme case edit`',
    )
  })

  it('names the case and its path', () => {
    const text = formatDecision(FIXTURES.OUT_OF_SCOPE, {
      casePath: 'work/acme/.guard/engagement.yaml',
    })
    expect(text).toContain('acme-ext-2026')
    expect(text).toContain('work/acme/.guard/engagement.yaml')
  })

  it('marks infrastructure-role targets', () => {
    expect(formatDecision(FIXTURES.INFRA_NOT_TARGET, CTX)).toContain(
      'registry.npmjs.org (infrastructure)',
    )
    expect(formatDecision(FIXTURES.OUT_OF_SCOPE, CTX)).not.toContain('(infrastructure)')
  })

  it('lists the opaque constructs', () => {
    const text = formatDecision(FIXTURES.OPAQUE_CONSTRUCT, CTX)
    expect(text).toContain('command-substitution')
    expect(text).toContain('variable')
  })

  it('stays within 12 lines with many targets and long values, offending targets first', () => {
    const targets = Array.from({ length: 40 }, (_, i) =>
      t(`192.0.2.${i}`, 'in-scope', 'in[0]: 192.0.2.0/24'),
    )
    targets.push(t('203.0.113.9', 'out-of-scope', 'out[0]: 203.0.113.0/24'))
    const a: GuardAnnotation = {
      ...FIXTURES.OUT_OF_SCOPE,
      targets,
      rule: 'x'.repeat(5000),
      detail: 'y'.repeat(5000),
      suggestion: 'z'.repeat(5000),
      opaque: ['variable', 'eval'],
    }
    const text = formatDecision(a, CTX)
    const lines = text.split('\n')
    expect(lines.length).toBeLessThanOrEqual(12)
    expect(text).toContain('203.0.113.9')
    expect(text).toMatch(/and 38 more targets/)
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(400)
    expect(text.endsWith(AUTHORISE)).toBe(true)
  })

  it('HARD_REFUSAL names the deny entry and its suggestion', () => {
    const text = formatDecision(FIXTURES.HARD_REFUSAL, CTX)
    expect(text).toContain(
      'Rule: nmap-script-dos: nmap --script selecting DoS scripts or categories that include them',
    )
    expect(text).toContain('Suggestion: --script "vuln and not dos"')
  })

  it('HARD_REFUSAL falls back to rule without a deny entry; the entry wins over rule', () => {
    const { denyEntry: _, ...noEntry } = FIXTURES.HARD_REFUSAL
    const fallback = formatDecision({ ...noEntry, rule: 'dos-tools: flood modes' }, CTX)
    expect(fallback).toContain('Rule: dos-tools: flood modes')
    const both = formatDecision({ ...FIXTURES.HARD_REFUSAL, rule: 'ignored rule text' }, CTX)
    expect(both).toContain('nmap-script-dos')
    expect(both).not.toContain('ignored rule text')
  })

  it('neutralises Unicode line separators and bidi controls', () => {
    const raw =
      'evil\u2028Injected\u2029x\u202Eexe.txt\u2066y\u2069\u202A\u202B\u202C\u202D\u2067\u2068'
    const text = formatDecision(
      { ...FIXTURES.OUT_OF_SCOPE, targets: [t(raw, 'out-of-scope', 'out[0]')] },
      CTX,
    )
    expect(text).not.toMatch(/[\u2028\u2029\u202a-\u202e\u2066-\u2069]/)
    expect(text).toContain('evil Injected x exe.txt y')
  })

  it('neutralises control characters and newlines in values', () => {
    const a: GuardAnnotation = {
      ...FIXTURES.OUT_OF_SCOPE,
      targets: [t('203.0.113.9\u001b[31m\nInjected: yes', 'out-of-scope', 'out[0]\r\nfake')],
    }
    const text = formatDecision(a, CTX)
    expect(text).not.toContain('\u001b')
    expect(text.split('\n').some((l) => l.startsWith('Injected'))).toBe(false)
    expect(text.split('\n').some((l) => l.startsWith('fake'))).toBe(false)
  })
})

describe('askPrompt', () => {
  it('exploitation confirmations are titled [EXPLOITATION]', () => {
    const p = askPrompt(
      FIXTURES.EXPLOITATION_CONFIRM,
      'sqlmap -u https://portal.acme.example/login',
    )
    expect(p.title.startsWith('[EXPLOITATION]')).toBe(true)
    expect(p.title).toContain('sqlmap -u https://portal.acme.example/login')
    expect(p.detail).toContain('EXPLOITATION_CONFIRM')
    expect(p.detail).toContain('https://portal.acme.example/login')
  })

  it('post-exploitation confirmations are titled [POST-EXPLOITATION]', () => {
    const p = askPrompt(
      { ...FIXTURES.EXPLOITATION_CONFIRM, tier: 'post-exploitation' },
      'impacket-psexec acme/admin@192.0.2.10',
    )
    expect(p.title.startsWith('[POST-EXPLOITATION]')).toBe(true)
  })

  it('an unskippable ask is never titled as an ordinary confirmation', () => {
    const p = askPrompt({ ...FIXTURES.EXPLOITATION_CONFIRM, tier: null }, 'msfconsole -x run')
    expect(p.title.startsWith('[EXPLOITATION]')).toBe(true)
  })

  it('ordinary asks name the reason code and stay within 12 detail lines', () => {
    for (const code of REASON_CODES) {
      const a = FIXTURES[code]
      if (a.verdict !== 'ask') continue
      const p = askPrompt(a, 'nmap -sV 192.0.2.10')
      expect(p.title).not.toMatch(/^\[(?:POST-)?EXPLOITATION\]/)
      expect(p.title).toContain('nmap -sV 192.0.2.10')
      expect(p.detail).toContain(code)
      expect(p.detail.split('\n').length).toBeLessThanOrEqual(12)
    }
  })

  it('keeps the title to one short line', () => {
    const p = askPrompt(FIXTURES.UNKNOWN_TARGET, `curl ${'a'.repeat(500)}\nrm -rf /`)
    expect(p.title).not.toContain('\n')
    expect(p.title.length).toBeLessThanOrEqual(160)
  })
})
