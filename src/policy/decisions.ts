import { z } from 'zod'
import type { OpaqueKind } from '../extract/tokenizer.js'
import { DEFAULT_COMMAND_HINT, DEFAULT_DIR } from '../paths.js'
import type { ScopeClass } from '../scope/engine.js'

/** Guard reason codes (plan Appendix B), in table order: deny, then ask-unskippable, ask, pass. */
export const REASON_CODES = [
  'HARD_REFUSAL',
  'PROTECTED_PATH',
  'FIRST_RUN_REQUIRED',
  'NO_ACTIVE_CASE',
  'CASE_INVALID',
  'NOT_ACKNOWLEDGED',
  'SCOPE_TAMPERED',
  'OUTSIDE_WINDOW',
  'BLACKOUT',
  'OUT_OF_SCOPE',
  'RESOLVES_OUT_OF_SCOPE',
  'RESOLVES_PRIVATE',
  'INFRA_NOT_TARGET',
  'TIER_NOT_AUTHORISED',
  'RATE_EXCEEDS_ROE',
  'AUDIT_UNAVAILABLE',
  'GUARD_ERROR',
  'EXPLOITATION_CONFIRM',
  'UNKNOWN_TARGET',
  'UNRESOLVABLE',
  'THIRD_PARTY_HOSTING',
  'RANGE_NOT_FULLY_AUTHORISED',
  'NO_TARGETS_FOUND',
  'OPAQUE_CONSTRUCT',
  'INTERPRETER_TARGETS',
  'POWERSHELL_NETWORK_TOOL',
  'IN_SCOPE',
  'OPERATOR_INFRA',
  'TRUSTED_INFRA',
  'LOCAL_TARGET',
  'NOT_NETWORK',
] as const
export type ReasonCode = (typeof REASON_CODES)[number]

/** Rules-of-engagement activity tiers. */
export const TierSchema = z.enum([
  'recon',
  'vuln-scan',
  'exploitation',
  'post-exploitation',
  'bruteforce',
])
export type Tier = z.infer<typeof TierSchema>

/** Guard outcome; `pass` delegates to core permission rules. */
export type GuardVerdict = 'deny' | 'ask' | 'ask-unskippable' | 'pass'

// ---- user-facing decision messages (P1 Task 9) --------------------------------------------------

/** One target as the guard decided it. */
export interface GuardTarget {
  raw: string
  class: ScopeClass
  /** The scope entry that decided the class (`"out[0]: 203.0.113.0/24"`), or `null`. */
  rule: string | null
  /** Addresses a hostname resolved to (formatted); `[]` when not resolved. */
  resolved: string[]
  /** `infra` for a host the tool only uses (proxy, DNS server, pivot); `target` when it is tested. */
  role?: 'target' | 'infra'
}

/** What the guard decided about one tool call and why: the input to every message. */
export interface GuardAnnotation {
  verdict: GuardVerdict
  reason: ReasonCode
  caseId: string | null
  tier: Tier | 'dos' | null
  targets: GuardTarget[]
  opaque: OpaqueKind[]
  /** The compliant alternative (`-T3`, `--rate 100`) when one exists. */
  suggestion: string | null
  /** The matched rule not tied to one target: denylist entry, RoE limit, window, blackout. */
  rule?: string
  /** The denylist entry behind a `HARD_REFUSAL`; rendered as the rule line in place of `rule`. */
  denyEntry?: { id: string; description: string }
  /** Extra context from the producer: a validation issue, an audit or guard error. */
  detail?: string
}

/** What the guidance names: the case file and the command that attests a change (`GuardPaths`). */
interface Hints {
  engagementPath: string
  commandHint: string
}

const AUTHORISE_SENTENCE = (h: Hints) =>
  `If the client has authorised this, the operator can update \`${h.engagementPath}\` and run \`${h.commandHint}\` (audited). Do not try to work around this check.`
const NO_WORKAROUND = 'Do not try to work around this check.'
const CORE_DECIDES = 'Core permission rules decide next.'

/** Per reason code: the headline and the closing guidance line (a function when it names a hint). */
const MESSAGES: Readonly<
  Record<ReasonCode, { headline: string; guidance: string | ((h: Hints) => string) }>
> = {
  HARD_REFUSAL: {
    headline: 'refused: the action is on the hard denylist',
    guidance: `Hard refusals cannot be approved or allowed by any case, mode, grant or setting. ${NO_WORKAROUND}`,
  },
  PROTECTED_PATH: {
    headline: 'refused: the model may not write the case file, scope snapshots, audit log or keys',
    guidance: (h) =>
      `The operator edits the case file outside the model and attests the change with \`${h.commandHint}\` (audited). ${NO_WORKAROUND}`,
  },
  FIRST_RUN_REQUIRED: {
    headline: 'security tools are locked until the first-run acknowledgement is completed',
    guidance: `The operator must complete the first-run acknowledgement (\`engagement-guard ack\`). ${NO_WORKAROUND}`,
  },
  NO_ACTIVE_CASE: {
    headline: 'no active case: remote network actions need an engagement',
    guidance:
      'The operator can create a case with `engagement-guard init`, then attest it with `engagement-guard engagement freeze`.',
  },
  CASE_INVALID: {
    headline: 'the case file failed validation',
    guidance:
      'The operator must fix the case file; `engagement-guard engagement validate` lists every error.',
  },
  NOT_ACKNOWLEDGED: {
    headline: 'the case scope has not been attested and frozen',
    guidance:
      'The operator must review the scope and attest it with `engagement-guard engagement freeze`.',
  },
  SCOPE_TAMPERED: {
    headline: 'the scope changed after it was frozen (scope hash mismatch)',
    guidance: `The operator must review the change and re-attest it with \`engagement-guard engagement freeze\`. ${NO_WORKAROUND}`,
  },
  OUTSIDE_WINDOW: {
    headline: 'outside the engagement window',
    guidance: (h) =>
      `Nothing overrides the window; only an audited \`${h.commandHint}\` changes it. ${NO_WORKAROUND}`,
  },
  BLACKOUT: {
    headline: 'inside a blackout period of the engagement',
    guidance: (h) =>
      `Nothing overrides blackout hours; only an audited \`${h.commandHint}\` changes them. ${NO_WORKAROUND}`,
  },
  OUT_OF_SCOPE: { headline: 'a target is out of scope', guidance: AUTHORISE_SENTENCE },
  RESOLVES_OUT_OF_SCOPE: {
    headline: 'a hostname resolves to an out-of-scope address',
    guidance: AUTHORISE_SENTENCE,
  },
  RESOLVES_PRIVATE: {
    headline: 'a hostname resolves to a private address on a non-internal case',
    guidance: AUTHORISE_SENTENCE,
  },
  INFRA_NOT_TARGET: {
    headline: 'trusted infrastructure is not a target',
    guidance: `Registries, code hosts and resolvers may be fetched from, never scanned, fuzzed, brute-forced or exploited. ${NO_WORKAROUND}`,
  },
  TIER_NOT_AUTHORISED: {
    headline: 'the rules of engagement do not authorise this tier',
    guidance: (h) =>
      `If the client has authorised this tier, the operator can add it to roe.allowed_test_classes with \`${h.commandHint}\` (audited). ${NO_WORKAROUND}`,
  },
  RATE_EXCEEDS_ROE: {
    headline: 'the rate or timing exceeds the RoE limit',
    guidance: (h) =>
      `Re-run with the compliant setting; RoE rate limits change only with \`${h.commandHint}\`.`,
  },
  AUDIT_UNAVAILABLE: {
    headline: 'the audit log cannot be written, so network actions fail closed',
    guidance:
      'The operator must restore the audit log (disk space, permissions), then check it with `engagement-guard audit verify`.',
  },
  GUARD_ERROR: {
    headline: 'internal error in the scope guard; the action failed closed',
    guidance: 'Tell the operator. Do not retry the action in another form.',
  },
  EXPLOITATION_CONFIRM: {
    headline: 'exploitation is authorised by the RoE but needs the operator to confirm',
    guidance: 'This confirmation can never be skipped, remembered or pre-approved.',
  },
  UNKNOWN_TARGET: {
    headline: 'a target matches no scope entry',
    guidance: (h) =>
      `The operator must confirm; if the target belongs to the engagement, add it with \`${h.commandHint}\`.`,
  },
  UNRESOLVABLE: {
    headline: 'an in-scope name did not resolve',
    guidance: 'The operator must confirm before the action runs.',
  },
  THIRD_PARTY_HOSTING: {
    headline: 'a target resolves outside the in-scope ranges (possible third-party hosting)',
    guidance: 'The operator must confirm that the client owns this hosting before it is tested.',
  },
  RANGE_NOT_FULLY_AUTHORISED: {
    headline: 'a range is only partly covered by the scope',
    guidance: 'Narrow the range to the in-scope part, or the operator must confirm.',
  },
  NO_TARGETS_FOUND: {
    headline: 'a known network tool with no target the guard could read',
    guidance: 'Name the targets explicitly on the command line, or the operator must confirm.',
  },
  OPAQUE_CONSTRUCT: {
    headline: 'the command uses constructs the guard cannot read',
    guidance: 'Write the targets literally, or the operator must confirm.',
  },
  INTERPRETER_TARGETS: {
    headline: 'an interpreter or unknown program is given network targets',
    guidance: 'The operator must confirm what this program does with these targets.',
  },
  POWERSHELL_NETWORK_TOOL: {
    headline: 'a PowerShell command names a network tool',
    guidance: 'The operator must confirm; PowerShell commands are not parsed for targets.',
  },
  IN_SCOPE: {
    headline: 'all targets are in scope; tier and rate are within the RoE',
    guidance: CORE_DECIDES,
  },
  OPERATOR_INFRA: {
    headline: 'the remaining targets are operator infrastructure',
    guidance: CORE_DECIDES,
  },
  TRUSTED_INFRA: {
    headline: 'trusted infrastructure used for fetch, VCS, packages, DNS or remote access',
    guidance: CORE_DECIDES,
  },
  LOCAL_TARGET: { headline: 'loopback targets only', guidance: CORE_DECIDES },
  NOT_NETWORK: { headline: 'not a network action', guidance: CORE_DECIDES },
}

const VERDICT_LABEL: Readonly<Record<GuardVerdict, string>> = {
  deny: 'DENIED',
  ask: 'NEEDS CONFIRMATION',
  'ask-unskippable': 'NEEDS CONFIRMATION (unskippable)',
  pass: 'PASS',
}

const MAX_VALUE = 200
const MAX_TARGET_LINES = 3
const MAX_RESOLVED = 3
const MAX_TITLE_SUMMARY = 120

/** C0/C1 controls, Unicode line/paragraph separators and bidi embedding/override/isolate controls. */
const UNSAFE_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]+/g

/** One line of plain text: control characters (ANSI escapes, newlines) become a space; long values are cut. */
function clean(value: string, max = MAX_VALUE): string {
  const flat = value.replace(UNSAFE_CHARS, ' ').trim()
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat
}

/** Targets that explain a deny come first; otherwise the producer's order is kept. */
const CLASS_ORDER: Readonly<Record<ScopeClass, number>> = {
  'out-of-scope': 0,
  'trusted-infra': 1,
  unknown: 2,
  'no-engagement': 3,
  'not-acknowledged': 3,
  'outside-window': 3,
  blackout: 3,
  'in-scope': 4,
  'operator-infra': 4,
  local: 4,
}

function targetLine(t: GuardTarget): string {
  const infra = t.role === 'infra' ? ' (infrastructure)' : ''
  const rule = t.rule === null ? 'no matching scope rule' : `rule ${clean(t.rule)}`
  let line = `Target: ${clean(t.raw)}${infra}: ${t.class}, ${rule}`
  if (t.resolved.length > 0) {
    const shown = t.resolved.slice(0, MAX_RESOLVED).map((r) => clean(r, 64))
    const more = t.resolved.length - shown.length
    line += `, resolves to ${shown.join(', ')}${more > 0 ? ` (+${more} more)` : ''}`
  }
  return line
}

/** The hints a caller passes (`GuardPaths`); missing ones are the defaults. */
export interface DecisionHints {
  /** The case file, relative to the workspace (default `.guard/engagement.yaml`). */
  engagementPath?: string
  /** The command that attests a scope change (default `engagement-guard engagement edit`). */
  commandHint?: string
}

const hintsOf = (h: DecisionHints): Hints => ({
  engagementPath: h.engagementPath ?? `${DEFAULT_DIR}/engagement.yaml`,
  commandHint: h.commandHint ?? DEFAULT_COMMAND_HINT,
})

/** Every line of a decision except the case line, which needs the caller's case path. */
function decisionParts(
  a: GuardAnnotation,
  hints: DecisionHints,
): { head: string; body: string[]; guidance: string } {
  const msg = MESSAGES[a.reason]
  const head = `engagement-guard: ${VERDICT_LABEL[a.verdict]} [${a.reason}]: ${msg.headline}`
  const body: string[] = []
  if (a.targets.length === 0) body.push('Targets: none extracted')
  else {
    const sorted = a.targets
      .map((t, i) => ({ t, i }))
      .sort((x, y) => CLASS_ORDER[x.t.class] - CLASS_ORDER[y.t.class] || x.i - y.i)
      .map((x) => x.t)
    for (const t of sorted.slice(0, MAX_TARGET_LINES)) body.push(targetLine(t))
    const more = sorted.length - MAX_TARGET_LINES
    if (more > 0) body.push(`… and ${more} more target${more === 1 ? '' : 's'}`)
  }
  if (a.denyEntry !== undefined)
    body.push(`Rule: ${clean(a.denyEntry.id, 64)}: ${clean(a.denyEntry.description)}`)
  else if (a.rule !== undefined) body.push(`Rule: ${clean(a.rule)}`)
  if (a.detail !== undefined) body.push(`Detail: ${clean(a.detail)}`)
  if (a.tier !== null) body.push(`Tier: ${a.tier}`)
  if (a.opaque.length > 0) body.push(`Opaque constructs: ${a.opaque.join(', ')}`)
  const label = a.reason === 'RATE_EXCEEDS_ROE' ? 'Compliant setting' : 'Suggestion'
  if (a.suggestion !== null) body.push(`${label}: ${clean(a.suggestion)}`)
  else if (a.reason === 'RATE_EXCEEDS_ROE')
    body.push('Compliant setting: lower the rate or timing to the RoE limit')
  const guidance = typeof msg.guidance === 'string' ? msg.guidance : msg.guidance(hintsOf(hints))
  return { head, body, guidance }
}

/**
 * The decision as the model and the operator read it: plain text, at most 12 lines, deterministic.
 * Nothing is redacted here (the audit layer redacts what it stores); control characters are removed.
 * `ctx` may carry the `GuardPaths` hints the guidance names.
 */
export function formatDecision(
  a: GuardAnnotation,
  ctx: { casePath: string } & DecisionHints,
): string {
  const { head, body, guidance } = decisionParts(a, ctx)
  const casePath = clean(ctx.casePath)
  const caseLine =
    a.caseId === null
      ? `Case: none active (expected at ${casePath})`
      : `Case: ${clean(a.caseId, 80)} (${casePath})`
  return [head, ...body, caseLine, guidance].join('\n')
}

/** The operator prompt for a guard ASK: a one-line title and the decision as its detail. */
export function askPrompt(
  a: GuardAnnotation,
  summary: string,
  hints: DecisionHints = {},
): { title: string; detail: string } {
  const label =
    a.verdict === 'ask-unskippable'
      ? a.tier === 'post-exploitation'
        ? '[POST-EXPLOITATION]'
        : '[EXPLOITATION]'
      : '[CONFIRM]'
  const { head, body, guidance } = decisionParts(a, hints)
  return {
    title: `${label} ${clean(summary, MAX_TITLE_SUMMARY)}`,
    detail: [head, ...body, guidance].join('\n'),
  }
}
