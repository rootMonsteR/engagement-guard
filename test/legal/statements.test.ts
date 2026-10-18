import { describe, expect, it } from 'vitest'
import { sha256Hex } from '../../src/canonical.js'
import { ATTESTATION_V1, FIRST_RUN_V1 } from '../../src/legal/statements.js'

/** Pinned: changing a statement's wording without bumping its version must fail here. */
describe('legal statements', () => {
  it('pins the first-run statement', () =>
    expect(sha256Hex(FIRST_RUN_V1)).toBe(
      '65fcc27572cfd5324999f5079f0bf7e75a963ac164823f93c23a3ff1acfb4aac',
    ))
  it('pins the attestation statement', () =>
    expect(sha256Hex(ATTESTATION_V1)).toBe(
      '413d9d5f0c4086b7a787706f6427c365f97b7dcf92ccd91ffd0a46b4c87797c9',
    ))
  it('names no product', () => {
    expect(FIRST_RUN_V1).not.toMatch(/nemesis/i)
    expect(ATTESTATION_V1).not.toMatch(/nemesis/i)
  })
})
