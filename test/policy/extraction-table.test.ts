import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { parse as parseYaml } from 'yaml'
import { z } from 'zod'
import { REASON_CODES } from '../../src/policy/decisions.js'
import { evaluateGuard, type GuardOutcome } from '../../src/policy/guard.js'
import {
  bashRequest,
  CWD,
  FIXTURES,
  fileRequest,
  guardHarness,
  loadTableCase,
} from './guard-helpers.js'

const CATEGORIES = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N'] as const

const RowSchema = z.strictObject({
  cat: z.enum(CATEGORIES),
  command: z.string().min(1),
  targets: z.array(z.string()),
  decision: z.enum(['deny', 'ask', 'ask-unskippable', 'pass']),
  reason: z.enum(REASON_CODES),
  case: z.enum(['default', 'exploit']).optional(),
  shell: z.enum(['posix', 'powershell']).optional(),
  tool: z.enum(['Bash', 'Write', 'Edit']).optional(),
  note: z.string().optional(),
})
type Row = z.infer<typeof RowSchema>

const ROWS: Row[] = z
  .array(RowSchema)
  .parse(parseYaml(readFileSync(join(FIXTURES, 'commands', 'extraction-table.yaml'), 'utf8')))

/** Plan §9 / brief minimums per category (N: ruling P24). */
const MINIMUMS: Record<(typeof CATEGORIES)[number], number> = {
  A: 7,
  B: 8,
  C: 8,
  D: 6,
  E: 5,
  F: 6,
  G: 6,
  H: 7,
  I: 7,
  J: 4,
  K: 5,
  L: 7,
  M: 3,
  N: 5,
}

const CASES = { default: loadTableCase('default'), exploit: loadTableCase('exploit') }

describe('extraction table: shape', () => {
  it('has at least 72 rows, with deny + ask at least 60 %', () => {
    expect(ROWS.length).toBeGreaterThanOrEqual(72)
    const restrictive = ROWS.filter((r) => r.decision !== 'pass').length
    expect(restrictive / ROWS.length).toBeGreaterThanOrEqual(0.6)
  })

  it('meets every category minimum', () => {
    for (const cat of CATEGORIES) {
      expect(ROWS.filter((r) => r.cat === cat).length, `category ${cat}`).toBeGreaterThanOrEqual(
        MINIMUMS[cat],
      )
    }
  })

  it('category specifics: C ≥ 6 OUT_OF_SCOPE, G ≥ 2 INFRA_NOT_TARGET, N has a PASS row', () => {
    const count = (cat: Row['cat'], reason: Row['reason']) =>
      ROWS.filter((r) => r.cat === cat && r.reason === reason).length
    expect(count('C', 'OUT_OF_SCOPE')).toBeGreaterThanOrEqual(6)
    expect(count('G', 'INFRA_NOT_TARGET')).toBeGreaterThanOrEqual(2)
    expect(ROWS.some((r) => r.cat === 'N' && r.decision === 'pass')).toBe(true)
  })
})

const label = (r: Row) =>
  `[${r.cat}] ${r.tool && r.tool !== 'Bash' ? `${r.tool} ` : ''}${r.command}${r.case === 'exploit' ? ' (exploit case)' : ''}`

describe('extraction table: extractor targets', () => {
  const h = guardHarness()
  for (const row of ROWS) {
    if (row.tool !== undefined && row.tool !== 'Bash') continue
    it(label(row), async () => {
      const a = await h.extractor.analyze(row.command, { cwd: CWD, shell: row.shell ?? 'posix' })
      expect(a.targets.map((t) => t.raw).sort()).toEqual([...row.targets].sort())
    })
  }
})

describe('extraction table: guard verdicts', () => {
  for (const row of ROWS) {
    it(`${label(row)} → ${row.decision} ${row.reason}`, async () => {
      const h = guardHarness({
        state: { status: 'active', case: CASES[row.case ?? 'default'] },
        shell: row.shell ?? 'posix',
      })
      const req =
        row.tool === 'Write' || row.tool === 'Edit'
          ? fileRequest(row.tool, row.command)
          : bashRequest(row.command)
      const out = await evaluateGuard(req, h.ctx)
      expect(out).not.toBe('not-inspected')
      const o = out as GuardOutcome
      expect({ decision: o.verdict, reason: o.reason }).toEqual({
        decision: row.decision,
        reason: row.reason,
      })
      expect(o.annotation.verdict).toBe(row.decision)
      expect(o.annotation.reason).toBe(row.reason)
      if (o.verdict === 'deny') {
        expect(o.message).toContain(`[${row.reason}]`)
        const hasRule =
          o.annotation.denyEntry !== undefined ||
          o.annotation.rule !== undefined ||
          o.annotation.targets.some((t) => t.rule !== null)
        expect(hasRule, 'a deny names the rule that decided it').toBe(true)
      }
    })
  }
})
