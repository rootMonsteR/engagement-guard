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
import { verifyAudit } from '../../src/audit/verify.js'
import { type AuditLog, createAuditLog } from '../../src/audit/writer.js'
import {
  type EngagementCommandContext,
  runEngagementCommand,
} from '../../src/engagement/commands.js'
import { ENGAGEMENT_PATH } from '../../src/engagement/load.js'
import { createCaseStore } from '../../src/engagement/store.js'
import { firstRunAckPath, recordFirstRunAck } from '../../src/first-run.js'
import type { Prompter } from '../../src/types.js'

const ACME = join(import.meta.dirname, '..', 'fixtures', 'engagements', 'acme-external.yaml')
const CASE_ID = 'acme-ext-2026q4'
const NOW = new Date('2026-10-21T08:00:00.000Z')
const now = () => NOW

let cwd: string
let home: string
let auditDir: string
let audit: AuditLog

beforeEach(async () => {
  cwd = await mkdtemp(join(tmpdir(), 'guard-eng-p1-'))
  home = await mkdtemp(join(tmpdir(), 'guard-eng-p1-home-'))
  await mkdir(join(cwd, '.guard'), { recursive: true })
  await copyFile(ACME, join(cwd, ENGAGEMENT_PATH))
  await recordFirstRunAck(home, 'alice', NOW)
  auditDir = join(cwd, '.guard', 'audit')
  audit = createAuditLog({ dir: auditDir, sessionId: 's-1', operator: 'alice', now })
})

afterEach(async () => {
  await rm(cwd, { recursive: true, force: true })
  await rm(home, { recursive: true, force: true })
})

const base = (extra: Partial<EngagementCommandContext> = {}): EngagementCommandContext => ({
  cwd,
  interactive: false,
  home,
  audit,
  now,
  ...extra,
})

const run = (argv: string[], extra: Partial<EngagementCommandContext> = {}) =>
  runEngagementCommand(argv, base(extra))

/** A UI that answers every question with `answer` and remembers the questions. */
function answering(answer: string): Prompter & { questions: string[] } {
  const questions: string[] = []
  return {
    questions,
    askUser: async (q) => {
      questions.push(q.question)
      return answer
    },
  }
}

async function widenScope(): Promise<void> {
  const file = join(cwd, ENGAGEMENT_PATH)
  const text = await readFile(file, 'utf8')
  const anchor = '    - https://portal.acme-partner.example:8443/app/\n'
  await writeFile(file, text.replace(anchor, `${anchor}    - 203.0.113.0/24\n`))
}

async function auditKinds(): Promise<string[]> {
  await audit.flush()
  const dir = join(auditDir, CASE_ID)
  const names = await readdir(dir).catch(() => [] as string[])
  const kinds: string[] = []
  for (const name of names.sort()) {
    for (const line of (await readFile(join(dir, name), 'utf8')).split('\n')) {
      if (line !== '') kinds.push(JSON.parse(line).kind)
    }
  }
  return kinds
}

describe('engagement freeze', () => {
  it('non-interactive without --attest exits 1 and changes nothing', async () => {
    const r = await run(['freeze'])
    expect(r.exitCode).toBe(1)
    expect(r.output).toContain('--attest acme-ext-2026q4')
    expect(r.output).toContain('status: unacknowledged')
    expect(await readFile(join(cwd, ENGAGEMENT_PATH), 'utf8')).toBe(await readFile(ACME, 'utf8'))
  })

  it('--attest with the wrong case id exits 1', async () => {
    const r = await run(['freeze', '--attest', 'wrong-id'])
    expect(r.exitCode).toBe(1)
    expect(r.output).toContain("'wrong-id'")
    expect(parseYaml(await readFile(join(cwd, ENGAGEMENT_PATH), 'utf8')).frozen).toBeUndefined()
  })

  it('--attest <caseId> freezes, attributes it to the acknowledged operator and audits it', async () => {
    const r = await run(['freeze', '--attest', CASE_ID])
    expect(r.exitCode).toBe(0)
    expect(r.output).toMatch(/^frozen: acme-ext-2026q4 scope_hash [0-9a-f]{64}$/m)
    expect(r.output).toMatch(/^status: active/m)
    expect(r.output).not.toContain('not audited')
    const yaml = parseYaml(await readFile(join(cwd, ENGAGEMENT_PATH), 'utf8'))
    expect(yaml.frozen.by).toBe('alice')
    expect(yaml.acknowledged_by.statement_version).toBe('attestation-v1')
    expect(await auditKinds()).toEqual(['case.freeze', 'case.activate'])
    expect((await verifyAudit(auditDir)).ok).toBe(true)
  })

  it('says so when it runs without an audit log', async () => {
    const r = await runEngagementCommand(['freeze', '--attest', CASE_ID], {
      cwd,
      interactive: false,
      home,
      now,
    })
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain('(not audited: no audit log)')
  })

  it('interactive: shows the attestation statement and asks for the case id', async () => {
    const ui = answering(CASE_ID)
    const r = await run(['freeze'], { interactive: true, ui })
    expect(r.exitCode).toBe(0)
    expect(ui.questions).toHaveLength(1)
    expect(ui.questions[0]).toContain('Case attestation (attestation-v1)')
    expect(ui.questions[0]).toContain('Type the case id to attest')
  })

  it('interactive: a different answer cancels', async () => {
    const r = await run(['freeze'], { interactive: true, ui: answering('nope') })
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/not attested/)
    expect(r.output).toContain('status: unacknowledged')
  })

  it('is refused before the first-run acknowledgement', async () => {
    await unlink(firstRunAckPath(home))
    const r = await run(['freeze', '--attest', CASE_ID])
    expect(r.exitCode).toBe(1)
    expect(r.output).toContain('status: first-run-required')
  })

  it('on an active case reports it is already frozen', async () => {
    await run(['freeze', '--attest', CASE_ID])
    const r = await run(['freeze', '--attest', CASE_ID])
    expect(r.exitCode).toBe(0)
    expect(r.output).toMatch(/already frozen/)
  })

  it('on a tampered case points to engagement-guard engagement edit', async () => {
    await run(['freeze', '--attest', CASE_ID])
    await widenScope()
    const r = await run(['freeze', '--attest', CASE_ID])
    expect(r.exitCode).toBe(1)
    expect(r.output).toContain('engagement-guard engagement edit')
    expect(r.output).toContain('status: tampered')
  })

  it('rejects stray arguments', async () => {
    const r = await run(['freeze', 'extra'])
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/Usage: engagement/)
  })
})

describe('engagement edit', () => {
  it('attests a changed scope and prints the diff', async () => {
    await run(['freeze', '--attest', CASE_ID])
    await widenScope()
    const r = await run(['edit', '--attest', CASE_ID])
    expect(r.exitCode).toBe(0)
    expect(r.output).toContain('+ "203.0.113.0/24"')
    expect(r.output).toMatch(/^status: active/m)
    expect(await auditKinds()).toEqual([
      'case.freeze',
      'case.activate',
      'case.edit',
      'case.activate',
    ])
  })

  it('interactive: shows the pending diff before asking', async () => {
    await run(['freeze', '--attest', CASE_ID])
    await widenScope()
    const ui = answering(CASE_ID)
    const r = await run(['edit'], { interactive: true, ui })
    expect(r.exitCode).toBe(0)
    expect(ui.questions[0]).toContain('+ "203.0.113.0/24"')
    expect(ui.questions[0]).toContain('Type the case id to attest')
  })

  it('non-interactive without --attest exits 1', async () => {
    await run(['freeze', '--attest', CASE_ID])
    await widenScope()
    const r = await run(['edit'])
    expect(r.exitCode).toBe(1)
    expect(r.output).toContain('status: tampered')
  })

  it('on a case never frozen points to engagement-guard engagement freeze', async () => {
    const r = await run(['edit', '--attest', CASE_ID])
    expect(r.exitCode).toBe(1)
    expect(r.output).toContain('engagement-guard engagement freeze')
  })
})

describe('engagement show / load', () => {
  it('show prints status, id, scope_hash, window, list counts and RoE tiers', async () => {
    const r = await run(['show'])
    expect(r.exitCode).toBe(0)
    const lines = r.output.split('\n')
    expect(lines[0]).toMatch(/^status: unacknowledged/)
    expect(r.output).toContain(`id: ${CASE_ID}`)
    expect(r.output).toMatch(/^scope_hash: [0-9a-f]{64}$/m)
    expect(r.output).toContain(
      'window: 2026-10-20T08:00:00+02:00 → 2026-10-31T18:00:00+01:00 (Europe/Amsterdam)',
    )
    expect(r.output).toContain('scope: 5 in, 3 out, 1 operator')
    expect(r.output).toContain('roe tiers: recon, vuln-scan')
    expect(r.output).toContain('frozen: no')
  })

  it('show reports the frozen hash of a tampered case', async () => {
    await run(['freeze', '--attest', CASE_ID])
    await widenScope()
    const r = await run(['show'])
    expect(r.exitCode).toBe(0)
    expect(r.output).toMatch(/^status: tampered/)
    expect(r.output).toMatch(/^frozen: .* by alice \(scope_hash [0-9a-f]{64}\)$/m)
  })

  it('show without a case says how to create one', async () => {
    await unlink(join(cwd, ENGAGEMENT_PATH))
    const r = await run(['show'])
    expect(r.exitCode).toBe(0)
    expect(r.output).toMatch(/^status: none/)
    expect(r.output).toContain('engagement-guard init')
  })

  it('show lists the issues of an invalid case', async () => {
    await writeFile(join(cwd, ENGAGEMENT_PATH), 'version: 1\n')
    const r = await run(['show'])
    expect(r.output).toMatch(/^status: invalid/)
    expect(r.output).toMatch(/^error /m)
  })

  it('load reloads the session store and prints the new status', async () => {
    const cases = await createCaseStore({ cwd, home, audit, now })
    await run(['freeze', '--attest', CASE_ID], { cases })
    expect(cases.state().status).toBe('active')
    await widenScope()
    expect(cases.state().status).toBe('active')
    const r = await run(['load'], { cases })
    expect(r.exitCode).toBe(0)
    expect(r.output).toMatch(/^status: tampered/)
    expect(cases.state().status).toBe('tampered')
  })

  it('needs the home when no store is supplied', async () => {
    const r = await runEngagementCommand(['show'], { cwd, interactive: false })
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/home/)
  })
})

describe('engagement usage', () => {
  it('lists the lifecycle subcommands', async () => {
    const r = await run(['--help'])
    expect(r.output).toMatch(/Usage: engagement <new\|validate\|show\|freeze\|edit\|load>/)
    for (const sub of ['show', 'freeze', 'edit', 'load']) {
      expect(r.output).toMatch(new RegExp(`^  ${sub} `, 'm'))
    }
  })
})

/** A UI that runs `before` (e.g. edits the file) and then answers with the case id. */
function racing(before: () => Promise<void>): Prompter & { questions: string[] } {
  const ui = answering(CASE_ID)
  const ask = ui.askUser
  ui.askUser = async (q) => {
    await before()
    return ask(q)
  }
  return ui
}

describe('fix round 1: pinned hashes, error mapping, show staleness', () => {
  it('interactive freeze shows the hash and refuses when the file changed before confirmation', async () => {
    const before = await readFile(join(cwd, ENGAGEMENT_PATH), 'utf8')
    const ui = racing(() => widenScope())
    const r = await run(['freeze'], { interactive: true, ui })
    expect(ui.questions[0]).toMatch(/scope_hash [0-9a-f]{64}/)
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/CASE_CHANGED|changed/)
    const after = await readFile(join(cwd, ENGAGEMENT_PATH), 'utf8')
    expect(after).not.toBe(before) // the operator's edit stays
    expect(parseYaml(after).frozen).toBeUndefined()
    expect(await auditKinds()).toEqual([])
  })

  it('interactive edit refuses when the file changed after the diff was shown', async () => {
    await run(['freeze', '--attest', CASE_ID])
    await widenScope()
    const file = join(cwd, ENGAGEMENT_PATH)
    const ui = racing(async () => {
      const text = await readFile(file, 'utf8')
      await writeFile(file, text.replace('rps: 50', 'rps: 500'))
    })
    const r = await run(['edit'], { interactive: true, ui })
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/changed/)
    expect(await auditKinds()).toEqual(['case.freeze', 'case.activate'])
  })

  it('maps an audit write failure to exit 1 instead of throwing', async () => {
    const blocker = join(cwd, 'not-a-dir')
    await writeFile(blocker, '')
    const broken = createAuditLog({ dir: blocker, sessionId: 's-1', operator: 'alice', now })
    const r = await run(['freeze', '--attest', CASE_ID], { audit: broken })
    expect(r.exitCode).toBe(1)
    expect(r.output).toMatch(/^cannot freeze: audit write failed/)
    expect(parseYaml(await readFile(join(cwd, ENGAGEMENT_PATH), 'utf8')).frozen).toBeUndefined()
    // A failed first freeze leaves no attestation history behind: still unacknowledged.
    expect(await readdir(join(cwd, '.guard', 'cases', CASE_ID)).catch(() => [])).toEqual([])
    const after = await run(['show'])
    expect(after.output).toMatch(/^status: unacknowledged/)
  })

  it('maps a failure while opening the store to exit 1', async () => {
    const r = await run(['show'], { home: join(cwd, '.guard', 'engagement.yaml', 'nested') })
    expect(r.exitCode).toBe(0) // a home that cannot hold an ack just means first-run-required
    const bad = join(cwd, 'dir-as-case')
    await mkdir(join(bad, '.guard', 'engagement.yaml'), { recursive: true })
    const r2 = await runEngagementCommand(['show'], { cwd: bad, interactive: false, home, now })
    expect(r2.exitCode).toBe(1)
    expect(r2.output).toMatch(/^cannot show: /)
  })

  it('show on a session store says the state is as of the last load', async () => {
    const cases = await createCaseStore({ cwd, home, audit, now })
    const r = await run(['show'], { cases })
    expect(r.output.split('\n')[0]).toMatch(/^status: unacknowledged .*\(as of last load\)$/)
    const fresh = await run(['show'])
    expect(fresh.output).not.toContain('as of last load')
  })
})

describe('fix round 2: freeze names the tamper reason', () => {
  async function dropKeys(...keys: string[]): Promise<void> {
    const file = join(cwd, ENGAGEMENT_PATH)
    const doc = parseDocument(await readFile(file, 'utf8'))
    for (const key of keys) doc.delete(key)
    await writeFile(file, String(doc))
  }

  const freeze = () => run(['freeze', '--attest', CASE_ID])

  it('scope-changed', async () => {
    await freeze()
    await widenScope()
    const r = await freeze()
    expect(r.exitCode).toBe(1)
    expect(r.output.split('\n')[0]).toBe(
      'cannot freeze: the scope of acme-ext-2026q4 changed since it was frozen; review and attest the change with engagement-guard engagement edit',
    )
  })

  it('attestation-removed', async () => {
    await freeze()
    await dropKeys('acknowledged_by')
    const r = await freeze()
    expect(r.exitCode).toBe(1)
    expect(r.output.split('\n')[0]).toMatch(/acknowledged_by block .* was removed/)
    expect(r.output).not.toContain('scope of acme-ext-2026q4 changed')
  })

  it('unfrozen', async () => {
    await freeze()
    await dropKeys('frozen', 'acknowledged_by')
    const r = await freeze()
    expect(r.exitCode).toBe(1)
    expect(r.output.split('\n')[0]).toMatch(/frozen block .* was removed without an audited edit/)
  })

  it('superseded', async () => {
    await freeze()
    const file = join(cwd, ENGAGEMENT_PATH)
    const frozenAtA = await readFile(file, 'utf8')
    await widenScope()
    await run(['edit', '--attest', CASE_ID])
    await writeFile(file, frozenAtA)
    const r = await freeze()
    expect(r.exitCode).toBe(1)
    expect(r.output.split('\n')[0]).toMatch(/older hash than its latest attestation/)
  })
})
