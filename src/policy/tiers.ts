import type { Engagement } from '../engagement/schema.js'
import type { SegmentAnalysis } from '../extract/extractor.js'
import type { Tier } from './decisions.js'

/** Tiers whose confirmation can never be skipped or pre-approved (spec §6.11, §10). */
export const ALWAYS_UNSKIPPABLE: ReadonlySet<Tier> = new Set<Tier>([
  'exploitation',
  'post-exploitation',
])

const RANK: Readonly<Record<Tier, number>> = {
  recon: 0,
  'vuln-scan': 1,
  bruteforce: 2,
  exploitation: 3,
  'post-exploitation': 4,
}

const atLeast = (t: Tier, floor: Tier): Tier => (RANK[t] >= RANK[floor] ? t : floor)

/**
 * The RoE tier one segment needs. `null` for a segment that is not a network action. `'dos'` for a
 * DoS tool or tier override, or when the extractor recorded a hard-deny flag. Otherwise the
 * extractor's base tier, raised to `exploitation` when the action is intrusive and the RoE does not
 * allow intrusive checks, or credentialed and the RoE does not allow credentialed testing.
 */
export function effectiveTier(seg: SegmentAnalysis, roe: Engagement['roe']): Tier | 'dos' | null {
  if (seg.hardDeny !== null) return 'dos'
  if (seg.tier === null || seg.nonNetwork) return null
  if (seg.tier === 'dos') return 'dos'
  let tier = seg.tier
  if (seg.intrusive && !roe.intrusive_checks) tier = atLeast(tier, 'exploitation')
  if (seg.credentials && !roe.credentialed_testing) tier = atLeast(tier, 'exploitation')
  return tier
}

/** Whether the RoE authorises `tier`. DoS is never authorised (`roe.dos_testing` is always false). */
export function tierAllowed(tier: Tier | 'dos', roe: Engagement['roe']): boolean {
  if (tier === 'dos') return false
  return roe.allowed_test_classes.includes(tier)
}
