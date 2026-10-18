import { execFileSync } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { subscribeAudit } from '../../src/audit/subscriber.js'
import { verifyAudit } from '../../src/audit/verify.js'
import { type AuditLog, createAuditLog } from '../../src/audit/writer.js'
import type { CaseState } from '../../src/engagement/store.js'
import type { TargetExtractor } from '../../src/extract/extractor.js'
import { resolvePaths } from '../../src/paths.js'
import type { GuardAnnotation, ReasonCode } from '../../src/policy/decisions.js'
import {
  createScopeGuard,
  evaluateGuard,
  type GuardContext,
  type GuardOutcome,
  installScopeGuard,
  isScopeGuardInstalled,
  wasInspected,
} from '../../src/policy/guard.js'
import type { Decision, GuardRequest } from '../../src/types.js'
import { createFakeEvents } from '../helpers/fake-events.js'
import { createFakeHost, type FakeHost } from '../helpers/fake-host.js'
import {
  bashRequest,
  CWD,
  fileRequest,
  guardHarness,
  HOME,
  loadTableCase,
  memoryAudit,
} from './guard-helpers.js'

const CASE = loadTableCase()
const OUTSIDE_WINDOW = new Date('2026-11-05T10:00:00+01:00')
const IN_BLACKOUT = new Date('2026-10-21T12:30:00+02:00')

let root: string

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'eg-guard-'))
})

afterEach(async () => {
  await rm(root, { recursive: true, force: true })
})

const annotationOf = (d: Decision): GuardAnnotation | undefined =>
  d.annotations?.guard as GuardAnnotation | undefined

function hostWith(ctx: GuardContext, opts: Parameters<typeof createFakeHost>[0] = {}): FakeHost {
  const host = createFakeHost({ mode: 'unrestricted', ...opts })
  installScopeGuard(host, createScopeGuard(ctx))
  return host
}

// ---- case-state matrix (28 cells) -----------------------------------------------------------------

interface StateCase {
  name: string
  state: CaseState
  now?: Date
  nmap: ReasonCode
}

const STATES: StateCase[] = [
  {
    name: 'first-run-required',
    state: { status: 'first-run-required' },
    nmap: 'FIRST_RUN_REQUIRED',
  },
  { name: 'none', state: { status: 'none' }, nmap: 'NO_ACTIVE_CASE' },
  {
    name: 'invalid',
    state: {
      status: 'invalid',
      path: join(CWD, '.guard', 'engagement.yaml'),
      issues: [
        {
          severity: 'error',
          path: 'window.end',
          code: 'WINDOW_INVERTED',
          message: 'end before start',
        },
      ],
    },
    nmap: 'CASE_INVALID',
  },
  {
    name: 'unacknowledged',
    state: { status: 'unacknowledged', case: CASE },
    nmap: 'NOT_ACKNOWLEDGED',
  },
  {
    name: 'tampered',
    state: { status: 'tampered', case: CASE, frozenHash: 'a'.repeat(64), reason: 'scope-changed' },
    nmap: 'SCOPE_TAMPERED',
  },
  {
    name: 'active-outside-window',
    state: { status: 'active', case: CASE },
    now: OUTSIDE_WINDOW,
    nmap: 'OUTSIDE_WINDOW',
  },
  {
    name: 'active-blackout',
    state: { status: 'active', case: CASE },
    now: IN_BLACKOUT,
    nmap: 'BLACKOUT',
  },
]

describe('guard: case-state matrix', () => {
  for (const s of STATES) {
    const harness = () => guardHarness({ state: s.state, ...(s.now ? { now: s.now } : {}) })

    it(`${s.name}: nmap 192.0.2.10 → deny ${s.nmap}`, async () => {
      const h = harness()
      const d = await hostWith(h.ctx).evaluate(bashRequest('nmap 192.0.2.10'))
      expect(d.kind).toBe('deny')
      expect(d.source).toBe('plugin')
      expect(annotationOf(d)).toMatchObject({ verdict: 'deny', reason: s.nmap })
      expect(d.kind === 'deny' && d.reason).toMatch(
        new RegExp(`^engagement-guard: DENIED \\[${s.nmap}\\]`),
      )
      expect(
        annotationOf(d)?.rule ?? annotationOf(d)?.detail,
        'the deny names its rule',
      ).toBeTruthy()
    })

    it(`${s.name}: git clone https://github.com/x/y → pass TRUSTED_INFRA`, async () => {
      const h = harness()
      const d = await hostWith(h.ctx).evaluate(bashRequest('git clone https://github.com/x/y'))
      expect(d.kind).toBe('allow')
      expect(annotationOf(d)).toMatchObject({ verdict: 'pass', reason: 'TRUSTED_INFRA' })
      if (s.state.status !== 'active') expect(h.lookups).toEqual([])
    })

    it(`${s.name}: curl http://localhost:3000 → pass LOCAL_TARGET`, async () => {
      const h = harness()
      const d = await hostWith(h.ctx).evaluate(bashRequest('curl http://localhost:3000'))
      expect(d.kind).toBe('allow')
      expect(annotationOf(d)).toMatchObject({ verdict: 'pass', reason: 'LOCAL_TARGET' })
    })

    it(`${s.name}: ls → pass NOT_NETWORK (P29: quiet without an active case)`, async () => {
      const audit = memoryAudit()
      const h = guardHarness({ state: s.state, audit, ...(s.now ? { now: s.now } : {}) })
      const host = hostWith(h.ctx)
      for (const cmd of ['ls', 'git status']) {
        const req = bashRequest(cmd)
        const d = await host.evaluate(req)
        expect(d.kind).toBe('allow')
        const o = (await evaluateGuard(req, h.ctx)) as GuardOutcome
        expect(o).toMatchObject({ verdict: 'pass', reason: 'NOT_NETWORK' })
        if (s.state.status === 'active') {
          expect(annotationOf(d)).toMatchObject({ verdict: 'pass', reason: 'NOT_NETWORK' })
          expect(wasInspected(req.toolUseId as string)).toBe(true)
        } else {
          expect(o.quiet).toBe(true)
          expect(annotationOf(d)).toBeUndefined()
          expect(wasInspected(req.toolUseId as string)).toBe(false)
        }
      }
      const decisions = audit.records.filter((r) => r.rec.kind === 'decision').length
      expect(decisions).toBe(s.state.status === 'active' ? 2 : 0)
    })

    it(`${s.name}: PowerShell package and VCS fetches pass TRUSTED_INFRA (I1)`, async () => {
      const h = guardHarness({
        state: s.state,
        shell: 'powershell',
        ...(s.now ? { now: s.now } : {}),
      })
      for (const cmd of [
        'npm install',
        'git pull',
        'git fetch origin',
        'pip install requests',
        'git clone https://github.com/x/y | Out-Null',
      ]) {
        const o = (await evaluateGuard(bashRequest(cmd), h.ctx)) as GuardOutcome
        expect({ cmd, verdict: o.verdict, reason: o.reason }).toEqual({
          cmd,
          verdict: 'pass',
          reason: 'TRUSTED_INFRA',
        })
      }
      const scan = (await evaluateGuard(bashRequest('nmap github.com'), h.ctx)) as GuardOutcome
      expect(scan.verdict).toBe('deny')
      if (s.state.status !== 'active') expect(h.lookups).toEqual([])
    })
  }

  it('the tampered deny names the tamper reason; the invalid deny the first issue', async () => {
    const tampered = await evaluateGuard(
      bashRequest('nmap 192.0.2.10'),
      guardHarness({ state: STATES[4]?.state as CaseState }).ctx,
    )
    expect((tampered as GuardOutcome).annotation.rule).toContain('scope-changed')
    const invalid = await evaluateGuard(
      bashRequest('nmap 192.0.2.10'),
      guardHarness({ state: STATES[2]?.state as CaseState }).ctx,
    )
    expect((invalid as GuardOutcome).message).toContain('window.end')
  })

  it('makes no DNS query without an active case (names matched statically)', async () => {
    for (const s of STATES.slice(0, 5)) {
      const h = guardHarness({ state: s.state })
      for (const cmd of [
        'nmap www.acme.example',
        'curl https://raw.githubusercontent.com/x/y/main/a.sh',
        'nmap github.com',
        'dig @8.8.8.8 github.com',
      ]) {
        const o = (await evaluateGuard(bashRequest(cmd), h.ctx)) as GuardOutcome
        expect(['deny', 'pass']).toContain(o.verdict)
      }
      expect(h.lookups).toEqual([])
    }
  })

  it('the coding agent works without a case: local and trusted actions pass', async () => {
    const h = guardHarness({ state: { status: 'none' } })
    const cases: [string, ReasonCode][] = [
      ["bash -c 'echo $HOME'", 'NOT_NETWORK'],
      [`python3 -c "print('a; b')"`, 'NOT_NETWORK'],
      ['git commit -m "fix: x; y"', 'NOT_NETWORK'],
      ['export PATH=$PATH:/opt/bin', 'NOT_NETWORK'],
      ['cd $DIR && ls', 'NOT_NETWORK'],
      ['npm install && npm test', 'TRUSTED_INFRA'],
      ['git pull && pnpm install', 'TRUSTED_INFRA'],
      ['curl -s http://127.0.0.1:5173/health', 'LOCAL_TARGET'],
    ]
    for (const [cmd, reason] of cases) {
      const o = (await evaluateGuard(bashRequest(cmd), h.ctx)) as GuardOutcome
      expect({ cmd, verdict: o.verdict, reason: o.reason }).toEqual({
        cmd,
        verdict: 'pass',
        reason,
      })
    }
    expect(h.lookups).toEqual([])
  })

  it('without a case, code the guard cannot read is denied, not passed', async () => {
    const h = guardHarness({ state: { status: 'none' } })
    for (const cmd of [
      'python3 -c "$CODE"',
      'eval "$X"',
      '$CMD',
      'bash -c "$X"',
      'git clone $REPO',
    ]) {
      const o = (await evaluateGuard(bashRequest(cmd), h.ctx)) as GuardOutcome
      expect({ cmd, reason: o.reason }).toEqual({ cmd, reason: 'NO_ACTIVE_CASE' })
    }
  })

  it('without an active case a scanner against trusted infrastructure is still denied', async () => {
    const h = guardHarness({ state: { status: 'none' } })
    const o = (await evaluateGuard(bashRequest('nmap github.com'), h.ctx)) as GuardOutcome
    expect(o).toMatchObject({ verdict: 'deny', reason: 'NO_ACTIVE_CASE' })
  })

  it('a hard refusal wins over every case state', async () => {
    const h = guardHarness({ state: { status: 'none' } })
    const o = (await evaluateGuard(bashRequest('hping3 --flood 192.0.2.10'), h.ctx)) as GuardOutcome
    expect(o).toMatchObject({ verdict: 'deny', reason: 'HARD_REFUSAL' })
    expect(o.annotation.denyEntry?.id).toBe('dos-tools')
  })
})

// ---- Review Focus 2: modes, rules and grants never weaken a guard ask -----------------------------

describe('guard: modes, allow rules and grants (Review Focus 2)', () => {
  it('unrestricted + allow rule + session grant: an unknown target still asks (plugin, no always-rule)', async () => {
    const h = guardHarness()
    // The fake host has no rules: its unrestricted core already allows what an allow rule would.
    const host = hostWith(h.ctx, { mode: 'unrestricted' })
    host.grant('Bash(nmap:*)', 'session')
    const d = await host.evaluate(bashRequest('nmap 192.0.2.200'))
    expect(d.kind).toBe('ask')
    expect(d.source).toBe('plugin')
    if (d.kind !== 'ask') throw new Error('unreachable')
    expect(d.prompt.allowAlwaysRule).toBeUndefined()
    expect(d.unskippable).toBe(false)
    expect(d.prompt.title).toContain('[CONFIRM]')
    expect(annotationOf(d)).toMatchObject({ verdict: 'ask', reason: 'UNKNOWN_TARGET' })
  })

  it('read-only: the mode deny wins and carries the annotation', async () => {
    const h = guardHarness()
    const d = await hostWith(h.ctx, { mode: 'read-only' }).evaluate(bashRequest('nmap 192.0.2.200'))
    expect(d.kind).toBe('deny')
    expect(d.source).toBe('mode')
    expect(annotationOf(d)).toMatchObject({ verdict: 'ask', reason: 'UNKNOWN_TARGET' })
  })

  it('plan mode: an in-scope pass still ends in the mode deny, annotated', async () => {
    const h = guardHarness()
    // The fake host has no plan mode; its core gives the deny plan mode would.
    const plan: Decision = { kind: 'deny', reason: 'plan mode', source: 'mode' }
    const d = await hostWith(h.ctx, { core: plan }).evaluate(bashRequest('nmap 192.0.2.10'))
    expect(d.kind).toBe('deny')
    expect(d.source).toBe('mode')
    expect(annotationOf(d)).toMatchObject({ verdict: 'pass', reason: 'IN_SCOPE' })
  })

  it('default mode, in scope: core asks with its always-rule, annotated pass', async () => {
    const h = guardHarness()
    const d = await hostWith(h.ctx, { mode: 'default' }).evaluate(bashRequest('nmap 192.0.2.10'))
    expect(d.kind).toBe('ask')
    if (d.kind !== 'ask') throw new Error('unreachable')
    expect(d.source).toBe('rule') // the fake core's ask (the original host core said 'mode'), not the guard's
    expect(d.prompt.allowAlwaysRule).toBe('Bash(nmap:*)')
    expect(annotationOf(d)).toMatchObject({ verdict: 'pass', reason: 'IN_SCOPE' })
  })

  it('a deny rule still wins over a guard ask', async () => {
    const h = guardHarness()
    const denyRule: Decision = { kind: 'deny', reason: 'deny rule Bash(nmap:*)', source: 'rule' }
    const d = await hostWith(h.ctx, { core: denyRule }).evaluate(bashRequest('nmap 192.0.2.200'))
    expect(d.kind).toBe('deny')
    expect(d.source).toBe('rule')
    expect(annotationOf(d)?.verdict).toBe('ask')
  })

  it('an authorised exploitation tier is an unskippable ask even in unrestricted mode', async () => {
    const h = guardHarness({ state: { status: 'active', case: loadTableCase('exploit') } })
    const host = hostWith(h.ctx, { mode: 'unrestricted' })
    host.grant('Bash(evil-winrm:*)', 'session')
    const d = await host.evaluate(bashRequest('evil-winrm -i 192.0.2.10 -u admin -p pw'))
    expect(d.kind).toBe('ask')
    if (d.kind !== 'ask') throw new Error('unreachable')
    expect(d.unskippable).toBe(true)
    expect(d.source).toBe('plugin')
    expect(d.prompt.allowAlwaysRule).toBeUndefined()
    expect(d.prompt.title).toContain('[POST-EXPLOITATION]')
  })

  it('a guard deny is final in unrestricted mode with allow rules and grants', async () => {
    const h = guardHarness()
    const host = hostWith(h.ctx, { mode: 'unrestricted' })
    host.grant('Bash', 'session')
    const d = await host.evaluate(bashRequest('nmap 203.0.113.5'))
    expect(d).toMatchObject({ kind: 'deny', source: 'plugin' })
  })

  it('a request at depth 1 (subagent) is evaluated identically', async () => {
    const h = guardHarness()
    for (const cmd of ['nmap 203.0.113.5', 'nmap 192.0.2.200', 'nmap 192.0.2.10', 'ls']) {
      const top = (await evaluateGuard(bashRequest(cmd), h.ctx)) as GuardOutcome
      const sub = (await evaluateGuard(bashRequest(cmd, { depth: 1 }), h.ctx)) as GuardOutcome
      expect({ v: sub.verdict, r: sub.reason, m: sub.message }).toEqual({
        v: top.verdict,
        r: top.reason,
        m: top.message,
      })
    }
  })
})

// ---- inspection, network-class tools, protected paths ---------------------------------------------

describe('guard: what it inspects', () => {
  it('Read is not inspected; Bash is, and stays inspected', async () => {
    const h = guardHarness()
    const read: GuardRequest = {
      ...fileRequest('Write', 'notes.txt'),
      toolName: 'Read',
      permissionClass: 'read',
    }
    expect(await evaluateGuard(read, h.ctx)).toBe('not-inspected')
    const host = hostWith(h.ctx)
    await host.evaluate(read)
    expect(wasInspected(read.toolUseId as string)).toBe(false)
    const bash = bashRequest('ls')
    await host.evaluate(bash)
    expect(wasInspected(bash.toolUseId as string)).toBe(true)
  })

  it('a Write to an ordinary file is not inspected; to the case file it is denied in any mode', async () => {
    const h = guardHarness({ state: { status: 'none' } })
    expect(await evaluateGuard(fileRequest('Write', 'notes.txt'), h.ctx)).toBe('not-inspected')
    const host = hostWith(h.ctx, { mode: 'unrestricted' })
    host.grant('Write', 'session')
    const d = await host.evaluate(fileRequest('Write', '.guard/engagement.yaml'))
    expect(d).toMatchObject({ kind: 'deny', source: 'plugin' })
    expect(annotationOf(d)).toMatchObject({ verdict: 'deny', reason: 'PROTECTED_PATH' })
    expect(d.kind === 'deny' && d.reason).toContain('engagement-guard engagement edit')
  })

  it("a deny is annotated under the product-neutral key 'guard' and no other", async () => {
    const host = hostWith(guardHarness().ctx)
    const d = await host.evaluate(bashRequest('nmap 203.0.113.5'))
    expect(d.kind).toBe('deny')
    expect(d.annotations?.guard).toMatchObject({ verdict: 'deny', reason: 'OUT_OF_SCOPE' })
    expect(Object.keys(d.annotations ?? {})).toEqual(['guard'])
  })

  it('protected paths: Windows-style and case-folded spellings, home keys, parents', async () => {
    const h = guardHarness()
    for (const cmd of [
      'echo x > .GUARD/Engagement.yaml',
      'echo x > .guard\\\\engagement.yaml',
      'cp evil.yaml ./.guard/./engagement.yaml',
      'rm -rf .guard',
      'rm -rf .',
      'truncate -s 0 .guard/audit/acme/s1.jsonl',
      'dd if=/dev/zero of=.guard/audit/acme/s1.jsonl',
      'chmod 000 .guard/audit',
      'ln -sf /tmp/x .guard/engagement.yaml',
      `rm -rf ${join(HOME, 'first-run.json').replace(/\\/g, '/')}`,
      `rm -rf ${join(HOME, 'keys').replace(/\\/g, '/')}`,
      'bash -c "rm -rf .guard/cases"',
    ]) {
      const o = (await evaluateGuard(bashRequest(cmd), h.ctx)) as GuardOutcome
      expect({ cmd, reason: o.reason }).toEqual({ cmd, reason: 'PROTECTED_PATH' })
    }
    for (const cmd of [
      'cat .guard/audit/acme/s1.jsonl',
      'cp .guard/engagement.yaml backup.yaml',
      'rm -rf build',
    ]) {
      const o = (await evaluateGuard(bashRequest(cmd), h.ctx)) as GuardOutcome
      expect({ cmd, reason: o.reason }).toEqual({ cmd, reason: 'NOT_NETWORK' })
    }
  })

  it('protected paths follow the workspace directory name of the paths', async () => {
    const h = guardHarness()
    const ctx = { ...h.ctx, paths: resolvePaths({ home: HOME, dirName: '.case', env: {} }) }
    for (const cmd of ['echo x > .case/engagement.yaml', 'rm -rf .case', 'rm -rf $X/.case']) {
      const o = (await evaluateGuard(bashRequest(cmd), ctx)) as GuardOutcome
      expect({ cmd, reason: o.reason }).toEqual({ cmd, reason: 'PROTECTED_PATH' })
    }
    const o = (await evaluateGuard(
      bashRequest('echo x > .guard/engagement.yaml'),
      ctx,
    )) as GuardOutcome
    expect(o.reason).toBe('NOT_NETWORK')
  })

  it('protected paths under PowerShell (whose tokenizer drops backslash separators)', async () => {
    const h = guardHarness({ shell: 'powershell' })
    for (const cmd of [
      String.raw`Remove-Item -Recurse -Force .guard\audit`,
      'Set-Content -Path .guard/engagement.yaml -Value x',
      String.raw`'x' | Out-File .guard\engagement.yaml`,
    ]) {
      const o = (await evaluateGuard(bashRequest(cmd), h.ctx)) as GuardOutcome
      expect({ cmd, reason: o.reason }).toEqual({ cmd, reason: 'PROTECTED_PATH' })
    }
    const read = (await evaluateGuard(
      bashRequest(String.raw`Get-Content .guard\engagement.yaml`),
      h.ctx,
    )) as GuardOutcome
    expect(read.reason).toBe('NOT_NETWORK')
  })

  it('a network-class tool is inspected through its declared targets or a literal sweep', async () => {
    const h = guardHarness()
    const req = (input: unknown): GuardRequest => ({
      ...bashRequest('x'),
      toolName: 'WebFetch',
      input,
      ruleKey: JSON.stringify(input),
      permissionClass: 'network',
    })
    const swept = (await evaluateGuard(req({ url: 'http://203.0.113.5/x' }), h.ctx)) as GuardOutcome
    expect(swept).toMatchObject({ verdict: 'deny', reason: 'OUT_OF_SCOPE' })
    const declared = (await evaluateGuard(req({ host: 'opaque' }), {
      ...h.ctx,
      networkTargets: () => ['192.0.2.10'],
    })) as GuardOutcome
    expect(declared).toMatchObject({ verdict: 'pass', reason: 'IN_SCOPE' })
    const none = (await evaluateGuard(req({ q: 'hello' }), h.ctx)) as GuardOutcome
    expect(none).toMatchObject({ verdict: 'ask', reason: 'NO_TARGETS_FOUND' })
    const noCase = guardHarness({ state: { status: 'none' } })
    const denied = (await evaluateGuard(
      req({ url: 'http://192.0.2.10/' }),
      noCase.ctx,
    )) as GuardOutcome
    expect(denied).toMatchObject({ verdict: 'deny', reason: 'NO_ACTIVE_CASE' })
  })

  it('P22: a --script refusal carries the denylist entry and its compliant suggestion', async () => {
    const h = guardHarness()
    const o = (await evaluateGuard(
      bashRequest('nmap --script vuln 192.0.2.10'),
      h.ctx,
    )) as GuardOutcome
    expect(o.reason).toBe('HARD_REFUSAL')
    expect(o.annotation.denyEntry?.id).toBe('nmap-script-dos')
    expect(o.annotation.suggestion).toContain('not dos')
  })

  it('a rate deny carries the compliant setting and the RoE limit', async () => {
    const h = guardHarness()
    const o = (await evaluateGuard(bashRequest('nmap -T5 192.0.2.10'), h.ctx)) as GuardOutcome
    expect(o.reason).toBe('RATE_EXCEEDS_ROE')
    expect(o.annotation.suggestion).toBe('-T3')
    expect(o.annotation.rule).toContain('nmap_max_timing')
  })

  it('isScopeGuardInstalled tracks installation and removal', () => {
    const h = guardHarness()
    const host = createFakeHost({ mode: 'default' })
    expect(isScopeGuardInstalled(host)).toBe(false)
    const off = installScopeGuard(host, createScopeGuard(h.ctx))
    expect(isScopeGuardInstalled(host)).toBe(true)
    off()
    expect(isScopeGuardInstalled(host)).toBe(false)
  })
})

// ---- audit and fail-closed ------------------------------------------------------------------------

describe('guard: audit and fail-closed', () => {
  it('writes the decision record before evaluate resolves (visible to an after-rules spy)', async () => {
    const dir = join(root, 'audit')
    const audit = createAuditLog({ dir, sessionId: 'sess-guard', operator: 'alice' })
    const h = guardHarness({ audit })
    const host = hostWith(h.ctx, { mode: 'unrestricted' })
    let seen = ''
    host.use(async (_req, next) => {
      seen = await readFile(join(dir, 'no-case', 'sess-guard.jsonl'), 'utf8')
      return next()
    }, 'after-rules')
    const req = bashRequest('nmap 192.0.2.10')
    const d = await host.evaluate(req)
    expect(d.kind).toBe('allow')
    const decision = seen
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => JSON.parse(l))
      .find((r) => r.kind === 'decision')
    expect(decision).toMatchObject({
      callId: req.toolUseId,
      tool: 'Bash',
      command: 'nmap 192.0.2.10',
      scope: { verdict: 'pass', reason: 'IN_SCOPE', tier: 'recon' },
      targets: [
        { raw: '192.0.2.10', class: 'in-scope', rule: 'in[2]: 192.0.2.0/25', resolved: [] },
      ],
    })
    await audit.flush()
    expect((await verifyAudit(dir)).ok).toBe(true)
  })

  it('a deny is written with sync before it returns', async () => {
    const audit = memoryAudit()
    const h = guardHarness({ audit })
    const d = await hostWith(h.ctx).evaluate(bashRequest('nmap 203.0.113.5'))
    expect(d.kind).toBe('deny')
    const rec = audit.records.find((r) => r.rec.kind === 'decision')
    expect(rec?.sync).toBe(true)
    expect(rec?.rec.scope).toEqual({ verdict: 'deny', reason: 'OUT_OF_SCOPE', tier: 'recon' })
  })

  it('a degraded audit log denies with AUDIT_UNAVAILABLE', async () => {
    const audit = memoryAudit()
    ;(audit as { degraded: boolean }).degraded = true
    const h = guardHarness({ audit })
    const d = await hostWith(h.ctx).evaluate(bashRequest('nmap 192.0.2.10'))
    expect(d.kind).toBe('deny')
    expect(annotationOf(d)).toMatchObject({ verdict: 'deny', reason: 'AUDIT_UNAVAILABLE' })
  })

  it('a failing audit write denies with AUDIT_UNAVAILABLE', async () => {
    const audit = memoryAudit()
    audit.fail = true
    const h = guardHarness({ audit })
    const d = await hostWith(h.ctx).evaluate(bashRequest('ls'))
    expect(d.kind).toBe('deny')
    expect(annotationOf(d)).toMatchObject({ verdict: 'deny', reason: 'AUDIT_UNAVAILABLE' })
  })

  it('an extractor that throws denies with GUARD_ERROR, and the deny is audited', async () => {
    const audit = memoryAudit()
    const broken: TargetExtractor = {
      analyze: async () => {
        throw new Error('boom')
      },
    }
    const h = guardHarness({ audit, extractor: broken })
    const d = await hostWith(h.ctx).evaluate(bashRequest('nmap 192.0.2.10'))
    expect(d.kind).toBe('deny')
    expect(annotationOf(d)).toMatchObject({
      verdict: 'deny',
      reason: 'GUARD_ERROR',
      detail: 'boom',
    })
    const rec = audit.records.find((r) => r.rec.kind === 'decision')
    expect(rec?.rec.scope).toMatchObject({ verdict: 'deny', reason: 'GUARD_ERROR' })
    expect(rec?.sync).toBe(true)
  })

  it('a case-state reader that throws denies with GUARD_ERROR', async () => {
    const h = guardHarness()
    const ctx: GuardContext = {
      ...h.ctx,
      caseState: () => {
        throw new Error('store gone')
      },
    }
    const d = await hostWith(ctx).evaluate(bashRequest('nmap 192.0.2.10'))
    expect(annotationOf(d)).toMatchObject({ verdict: 'deny', reason: 'GUARD_ERROR' })
  })

  it('a held tool.call (no active case) lands before the guard decision record', async () => {
    const dir = join(root, 'audit')
    const audit: AuditLog = createAuditLog({ dir, sessionId: 'sess-order', operator: 'alice' })
    const events = createFakeEvents()
    subscribeAudit(events, audit, { caseActive: () => false, inspected: wasInspected })
    const h = guardHarness({ audit, state: { status: 'none' } })
    const host = hostWith(h.ctx, { mode: 'unrestricted' })
    const req = bashRequest('nmap 192.0.2.10')
    events.emit({
      type: 'tool.call',
      toolUseId: req.toolUseId as string,
      name: 'Bash',
      input: { command: 'nmap 192.0.2.10' },
      summary: 'nmap',
    })
    const decision = await host.evaluate(req)
    // The event a harness emits for the decision (the subscriber skips the guard's own).
    events.emit({ type: 'permission.decision', toolUseId: req.toolUseId as string, decision })
    await audit.flush()
    const text = await readFile(join(dir, 'no-case', 'sess-order.jsonl'), 'utf8')
    const kinds = text
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => JSON.parse(l).kind)
    expect(kinds).toEqual(['tool.call', 'decision'])
  })
})

// ---- P1b demo -------------------------------------------------------------------------------------

describe('P1b demo: the guard in a running agent', () => {
  it('denies an out-of-scope nmap with the reason as the deny message, and leaves a verifiable audit trail', async () => {
    const dir = join(root, 'audit')
    const audit = createAuditLog({ dir, sessionId: 'sess-demo', operator: 'alice' })
    audit.setCase(CASE.engagement.id)
    const events = createFakeEvents()
    subscribeAudit(events, audit, { caseActive: () => true, inspected: wasInspected })
    const host = hostWith(guardHarness({ audit }).ctx, { mode: 'unrestricted' })
    // The events a harness emits around the call: tool.call, the decision, the (denied) result.
    const req = bashRequest('nmap 203.0.113.5', { toolUseId: 'toolu_demo' })
    events.emit({
      type: 'tool.call',
      toolUseId: 'toolu_demo',
      name: 'Bash',
      input: req.input,
      summary: req.summary,
    })
    const d = await host.evaluate(req)
    events.emit({ type: 'permission.decision', toolUseId: 'toolu_demo', decision: d })
    expect(d.kind).toBe('deny')
    if (d.kind !== 'deny') throw new Error('unreachable')
    expect(d.reason).toMatch(/^engagement-guard: DENIED \[OUT_OF_SCOPE\]/)
    expect(d.reason).toContain('Target: 203.0.113.5: out-of-scope, rule out[3]: 203.0.113.0/24')
    events.emit({
      type: 'tool.result',
      toolUseId: 'toolu_demo',
      name: 'Bash',
      isError: true,
      durationMs: 0,
      content: `Permission denied: ${d.reason}`,
    })
    await audit.flush()
    const report = await verifyAudit(dir)
    expect(report.ok).toBe(true)
    const text = await readFile(join(dir, CASE.engagement.id, 'sess-demo.jsonl'), 'utf8')
    const kinds = text
      .split('\n')
      .filter((l) => l !== '')
      .map((l) => JSON.parse(l).kind)
    expect(kinds).toContain('decision')
    expect(kinds.indexOf('tool.call')).toBeLessThan(kinds.indexOf('decision'))
    expect(kinds.at(-1)).toBe('tool.result')
  })
})

// ---- fix round 1 ----------------------------------------------------------------------------------

const writeRequest = (file: string, cwd = CWD): GuardRequest => ({
  ...fileRequest('Write', 'placeholder.txt'),
  input: { file_path: file, content: 'x' },
  ruleKey: file,
  cwd,
})

const reasonOf = async (req: GuardRequest, ctx: GuardContext) => {
  const o = await evaluateGuard(req, ctx)
  return o === 'not-inspected' ? o : o.reason
}

describe.runIf(process.platform === 'win32')('protected paths: Windows path forms (C1)', () => {
  it('device, verbatim and UNC prefixes, streams and trailing dots resolve to the protected path', async () => {
    const h = guardHarness({ state: { status: 'none' } })
    const caseFile = join(CWD, '.guard', 'engagement.yaml')
    for (const file of [
      `\\\\?\\${join(HOME, 'first-run.json')}`,
      `\\\\.\\${caseFile}`,
      `//?/${caseFile.replace(/\\/g, '/')}`,
      `${caseFile}::$DATA`,
      `${caseFile}:evil`,
      `${caseFile}.`,
      `${join(CWD, '.guard', 'audit ')}\\acme\\s1.jsonl`,
    ]) {
      expect({ file, reason: await reasonOf(writeRequest(file), h.ctx) }).toEqual({
        file,
        reason: 'PROTECTED_PATH',
      })
    }
    const unc = { ...h.ctx, paths: { ...h.ctx.paths, home: '\\\\server\\share\\guard-home' } }
    const uncFile = '\\\\?\\UNC\\server\\share\\guard-home\\keys\\audit.key'
    expect(await reasonOf(writeRequest(uncFile), unc)).toBe('PROTECTED_PATH')
    const bash = `echo x > '\\\\?\\${caseFile}'`
    expect(await reasonOf(bashRequest(bash), h.ctx)).toBe('PROTECTED_PATH')
  })

  it('8.3 short names resolve to the protected path (Write and Bash)', async (t) => {
    const ws = join(root, 'workspace-with-a-long-name')
    mkdirSync(join(ws, '.guard'), { recursive: true })
    const file = join(ws, '.guard', 'engagement.yaml')
    writeFileSync(file, 'version: 1\n')
    const short = execFileSync(
      'powershell.exe',
      [
        '-NoProfile',
        '-Command',
        `(New-Object -ComObject Scripting.FileSystemObject).GetFile('${file}').ShortPath`,
      ],
      { encoding: 'utf8' },
    ).trim()
    if (short === '' || short.toLowerCase() === file.toLowerCase()) t.skip() // 8.3 names disabled
    const h = guardHarness({ state: { status: 'none' } })
    expect(await reasonOf(writeRequest(short, ws), h.ctx)).toBe('PROTECTED_PATH')
    const bash = { ...bashRequest(`echo x > '${short.replace(/\\/g, '/')}'`), cwd: ws }
    expect(await reasonOf(bash, h.ctx)).toBe('PROTECTED_PATH')
  })
})

describe('guard: fix round 1', () => {
  it('M3: the case workspace stays protected from a different request cwd', async () => {
    const ws = join(root, 'ws')
    const moved = { ...CASE, path: join(ws, '.guard', 'engagement.yaml') }
    const h = guardHarness({ state: { status: 'active', case: moved } })
    const audit = `${join(ws, '.guard', 'audit').replace(/\\/g, '/')}`
    expect(await reasonOf(bashRequest(`rm -rf ${audit}`), h.ctx)).toBe('PROTECTED_PATH')
    expect(await reasonOf(writeRequest(join(ws, '.guard', 'engagement.yaml')), h.ctx)).toBe(
      'PROTECTED_PATH',
    )
    const other = join(root, 'store-cwd')
    const none = { ...guardHarness({ state: { status: 'none' } }).ctx, workspace: other }
    const target = `${join(other, '.guard', 'engagement.yaml').replace(/\\/g, '/')}`
    expect(await reasonOf(bashRequest(`echo x > ${target}`), none)).toBe('PROTECTED_PATH')
  })

  it('M1: an exception from the later stages denies with GUARD_ERROR, audited', async () => {
    const audit = memoryAudit()
    const h = guardHarness({ audit })
    const host = hostWith(h.ctx)
    host.use(async () => {
      throw new Error('after-rules exploded')
    }, 'after-rules')
    const d = await host.evaluate(bashRequest('nmap 192.0.2.10'))
    expect(d).toMatchObject({ kind: 'deny', source: 'plugin' })
    expect(annotationOf(d)).toMatchObject({ reason: 'GUARD_ERROR', detail: 'after-rules exploded' })
    const errors = audit.records.filter(
      (r) => r.rec.kind === 'decision' && r.rec.scope?.reason === 'GUARD_ERROR',
    )
    expect(errors).toHaveLength(1)
    expect(errors[0]?.sync).toBe(true)
  })

  it('M2: fail-closed denies name a rule', async () => {
    const degraded = memoryAudit()
    ;(degraded as { degraded: boolean }).degraded = true
    const a = await hostWith(guardHarness({ audit: degraded }).ctx).evaluate(bashRequest('ls'))
    expect(annotationOf(a)).toMatchObject({
      reason: 'AUDIT_UNAVAILABLE',
      rule: 'audit log degraded',
    })
    const broken: TargetExtractor = {
      analyze: async () => {
        throw new TypeError('bad')
      },
    }
    const b = await hostWith(guardHarness({ extractor: broken }).ctx).evaluate(bashRequest('ls'))
    expect(annotationOf(b)).toMatchObject({
      reason: 'GUARD_ERROR',
      rule: 'guard exception: TypeError',
    })
  })

  it('M5 (P12): a loopback target the case lists in out is out of scope, not local', async () => {
    const active = guardHarness()
    expect(await reasonOf(bashRequest('nmap 127.0.0.2'), active.ctx)).toBe('OUT_OF_SCOPE')
    expect(await reasonOf(bashRequest('nmap 127.0.0.1'), active.ctx)).toBe('LOCAL_TARGET')
    const tampered = guardHarness({ state: STATES[4]?.state as CaseState })
    expect(await reasonOf(bashRequest('nmap 127.0.0.2'), tampered.ctx)).toBe('SCOPE_TAMPERED')
  })

  it('M8: installs are reference-counted', () => {
    const h = guardHarness()
    const host = createFakeHost({ mode: 'default' })
    const off1 = installScopeGuard(host, createScopeGuard(h.ctx))
    const off2 = installScopeGuard(host, createScopeGuard(h.ctx))
    off1()
    off1()
    expect(isScopeGuardInstalled(host)).toBe(true)
    off2()
    expect(isScopeGuardInstalled(host)).toBe(false)
  })

  it('P29: a GUARD_ERROR still marks the call inspected; a quiet pass does not', async () => {
    const broken: TargetExtractor = {
      analyze: async () => {
        throw new Error('boom')
      },
    }
    const h = guardHarness({ state: { status: 'none' }, extractor: broken })
    const req = bashRequest('ls')
    await hostWith(h.ctx).evaluate(req)
    expect(wasInspected(req.toolUseId as string)).toBe(true)
  })
})

// ---- fix round 2 ----------------------------------------------------------------------------------

describe('guard: fix round 2', () => {
  const COMPUTED = [
    'git clone (Get-Content r.txt)',
    'git clone (gc r)',
    'git clone -- (gc r)',
    'git pull (gc r)',
    'git clone @args',
    'git fetch @a',
    'npm install (Get-Content pkgs.txt)',
    'pip install (gc wheel.txt)',
    'git clone "$(gc r)"',
    'git clone $u',
    '& git clone (gc r)',
  ]

  it('N1: PowerShell arguments computed at run time never pass as an implicit registry', async () => {
    for (const s of [STATES[1], STATES[4]] as StateCase[]) {
      const h = guardHarness({ state: s.state, shell: 'powershell' })
      for (const cmd of COMPUTED) {
        const o = (await evaluateGuard(bashRequest(cmd), h.ctx)) as GuardOutcome
        expect({ state: s.name, cmd, reason: o.reason }).toEqual({
          state: s.name,
          cmd,
          reason: s.nmap,
        })
      }
    }
    const active = guardHarness({ shell: 'powershell' })
    for (const cmd of COMPUTED) {
      const o = (await evaluateGuard(bashRequest(cmd), active.ctx)) as GuardOutcome
      expect({ cmd, verdict: o.verdict }).toEqual({ cmd, verdict: 'ask' })
      expect(['OPAQUE_CONSTRUCT', 'POWERSHELL_NETWORK_TOOL']).toContain(o.reason)
    }
  })

  it('M10: an exception from core on a quiet or uninspected path still fails closed', async () => {
    const audit = memoryAudit()
    const h = guardHarness({ state: { status: 'none' }, audit })
    const host = hostWith(h.ctx)
    host.use(async () => {
      throw new Error('core exploded')
    }, 'after-rules')
    const quiet = await host.evaluate(bashRequest('ls'))
    expect(quiet).toMatchObject({ kind: 'deny', source: 'plugin' })
    expect(annotationOf(quiet)).toMatchObject({ reason: 'GUARD_ERROR', detail: 'core exploded' })
    const read: GuardRequest = {
      ...fileRequest('Write', 'notes.txt'),
      toolName: 'Read',
      permissionClass: 'read',
    }
    const uninspected = await host.evaluate(read)
    expect(annotationOf(uninspected)).toMatchObject({ reason: 'GUARD_ERROR' })
    expect(audit.records).toEqual([])
  })
})

describe.runIf(process.platform === 'win32')(
  'protected paths: non-drive Windows paths (C1)',
  () => {
    it('admin shares, UNC, volume GUID and GLOBALROOT paths are protected by name', async () => {
      const h = guardHarness({ state: { status: 'none' } })
      const caseFile = join(CWD, '.guard', 'engagement.yaml')
      const noDrive = (p: string) => p.slice(2)
      for (const file of [
        `\\\\localhost\\c$${noDrive(caseFile)}`,
        `\\\\127.0.0.1\\C$${noDrive(caseFile)}`,
        `\\\\?\\UNC\\localhost\\c$${noDrive(caseFile)}`,
        `\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}${noDrive(caseFile)}`,
        `\\\\?\\GLOBALROOT\\??\\${caseFile}`,
        `\\\\.\\GLOBALROOT\\??\\${caseFile}`,
        `\\\\127.0.0.1\\C$${noDrive(join(HOME, 'keys', 'audit.key'))}`,
      ]) {
        expect({ file, reason: await reasonOf(writeRequest(file), h.ctx) }).toEqual({
          file,
          reason: 'PROTECTED_PATH',
        })
      }
      for (const target of [
        `\\\\localhost\\c$${noDrive(caseFile)}`,
        `\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}${noDrive(caseFile)}`,
      ]) {
        expect(await reasonOf(bashRequest(`echo x > '${target}'`), h.ctx)).toBe('PROTECTED_PATH')
      }
      expect(await reasonOf(writeRequest('\\\\fileserver\\share\\notes.txt'), h.ctx)).toBe(
        'not-inspected',
      )
    })
  },
)
