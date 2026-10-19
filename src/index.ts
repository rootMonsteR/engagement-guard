// Extracted from the Nemesis project's packages/sec (snapshot 2026-10-18). Source comments that cite
// a spec section (§) or a ruling (P<n>) refer to that project's unpublished design documents, kept
// as provenance; the behaviour contract is docs/decision-matrix.md and the extraction table.
export const VERSION = '0.1.0'

export type { AuditRecord } from './audit/record.js'
export {
  AUDIT_KINDS,
  AuditRecordSchema,
  AuditTargetSchema,
  genesisHash,
  hashRecord,
} from './audit/record.js'
export { CanonicalJsonError, canonicalJson, sha256Hex } from './canonical.js'
export { ATTESTATION_V1, FIRST_RUN_V1, STATEMENTS } from './legal/statements.js'
export type { GuardPaths } from './paths.js'
export {
  DEFAULT_COMMAND_HINT,
  DEFAULT_DIR,
  HOME_ENV,
  OPERATOR_ENV,
  resolvePaths,
} from './paths.js'
export type { GuardVerdict, ReasonCode, Tier } from './policy/decisions.js'
export { REASON_CODES, TierSchema } from './policy/decisions.js'
// --- scope: ip (P1 Task 3) ---
export type { IpAddr, IpClass, IpFamily, IpRange } from './scope/ip.js'
export {
  classesInRange,
  classifyIp,
  coveredBy,
  formatIp,
  formatRange,
  ipv6Embeddings,
  isPrivateLike,
  parseCidr,
  parseIp,
  parseIpRange,
  parseIpSpec,
  rangeContains,
  rangesIntersect,
  subtractRanges,
} from './scope/ip.js'
// --- end scope: ip ---

// --- scope: hostname + target (P1 Task 4) ---
export type { HostPattern } from './scope/hostname.js'
export {
  FILE_EXTENSIONS,
  hostMatches,
  looksLikeFqdn,
  normaliseHostname,
  parseHostPattern,
} from './scope/hostname.js'
export type { Target } from './scope/target.js'
export { parseTarget, targetHost } from './scope/target.js'
// --- end scope: hostname + target ---

// --- scope: engine, resolver, trusted infra, time (P1 Task 7) ---
export type {
  ClassifyOptions,
  ScopeClass,
  ScopeEngine,
  TargetVerdict,
} from './scope/engine.js'
export { createScopeEngine } from './scope/engine.js'
export type { LookupFn, ResolveResult, Resolver } from './scope/resolver.js'
export {
  createResolver,
  DEFAULT_LOOKUP_TIMEOUT_MS,
  DEFAULT_MAX_ENTRIES,
  MAX_DNS_TTL_MS,
} from './scope/resolver.js'
export type { TimeCheck } from './scope/time.js'
export { checkTime } from './scope/time.js'
export { compileTrustedInfra, DEFAULT_TRUSTED_INFRA } from './scope/trusted-infra.js'
// --- end scope engine ---

// --- engagement: schema, load, compile, template (P1 Task 5) ---
export type { CompiledList, CompiledScope, UrlEntry } from './engagement/compile.js'
export { compileScope } from './engagement/compile.js'
export type { LoadedCase, LoadResult, ValidationIssue } from './engagement/load.js'
export {
  computeScopeHash,
  ENGAGEMENT_PATH,
  KNOWN_TRUSTED_HOSTS,
  loadEngagement,
  parseEngagement,
} from './engagement/load.js'
export type { Engagement, ScopeEntry } from './engagement/schema.js'
export {
  BlackoutSchema,
  CASE_PROFILES,
  CASE_TYPES,
  EngagementSchema,
  RateLimitsSchema,
  RESERVED_CASE_TYPES,
  ScopeEntrySchema,
} from './engagement/schema.js'
export type { ScaffoldOptions } from './engagement/template.js'
export { scaffoldEngagement } from './engagement/template.js'
// --- end engagement ---

// --- engagement: commands (P1 Task 6) ---
export type { CommandOutcome, EngagementCommandContext } from './engagement/commands.js'
export { runEngagementCommand } from './engagement/commands.js'
// --- end engagement commands ---

// --- audit: redact, writer, subscriber, verify, export (P1 Task 10) ---
export type { AuditManifest } from './audit/export.js'
export {
  AUDIT_KEY_FILE,
  AuditManifestSchema,
  DEFAULT_MAX_BUNDLE_BYTES,
  exportAudit,
  verifyAuditBundle,
} from './audit/export.js'
export type { IndexEntry, VerifyError, VerifyErrorCode } from './audit/layout.js'
export { IndexEntrySchema } from './audit/layout.js'
export { LockTimeoutError, withChainLock } from './audit/lock.js'
export { REDACTED, redact, redactDeep } from './audit/redact.js'
export { subscribeAudit } from './audit/subscriber.js'
export type { TarEntry } from './audit/tar.js'
export { readTarGz, TarTooLargeError, writeTarGz } from './audit/tar.js'
export type { AuditSource, VerifyFileReport, VerifyReport } from './audit/verify.js'
export { verifyAudit } from './audit/verify.js'
export type { AuditLog, AuditRecordInput } from './audit/writer.js'
export { createAuditLog, NO_CASE } from './audit/writer.js'
export type { CreateGuardOptions, Guard } from './guard.js'
export { createGuard } from './guard.js'
// --- end audit ---

// --- case lifecycle: first-run, store, diff (P1 Task 12) ---
export { caseStatusLine } from './engagement/commands.js'
export type { DiffEntry } from './engagement/diff.js'
export { diffValues, renderDiff, scopeDiff } from './engagement/diff.js'
export { scopeHashInput } from './engagement/load.js'
export type {
  Attestation,
  CaseLifecycleCode,
  CaseState,
  CaseStore,
  EditResult,
  PendingEdit,
  SnapshotStatus,
  TamperReason,
} from './engagement/store.js'
export {
  BASE_UNAVAILABLE,
  CASE_SNAPSHOT_DIR,
  CaseLifecycleError,
  createCaseStore,
  PROTECTED_HOME_ENTRIES,
  protectedCasePaths,
  scopeSnapshotPath,
} from './engagement/store.js'
export type { FirstRunAck, LegalStatement } from './first-run.js'
export {
  ATTESTATION_STATEMENT_VERSION,
  FIRST_RUN_STATEMENT_VERSION,
  firstRunAckPath,
  hostFingerprint,
  loadFirstRunAck,
  readAttestationStatement,
  readFirstRunStatement,
  recordFirstRunAck,
  resolveOperator,
} from './first-run.js'
// --- end case lifecycle ---

// --- extract: tokenizer, tools table, literals, rate, extractor (P1 Task 8) ---
export type {
  CommandAnalysis,
  ExtractContext,
  ExtractedTarget,
  SegmentAnalysis,
  TargetExtractor,
  TargetExtractorOptions,
} from './extract/extractor.js'
export { createTargetExtractor } from './extract/extractor.js'
export type { ListFileFs, ListFileHandle } from './extract/list-file.js'
export { createListFileReader } from './extract/list-file.js'
export type { LiteralHit } from './extract/literals.js'
export { sweepLiterals } from './extract/literals.js'
export type { RateField, RateFlags, RateKind, RateLimits, RateViolation } from './extract/rate.js'
export { addRate, checkRate, parseRateValue, RATE_FIELD } from './extract/rate.js'
export type { OpaqueKind, Redirect, Segment } from './extract/tokenizer.js'
export { programName, stripWrappers, tokenizeCommand, WRAPPERS } from './extract/tokenizer.js'
export type { EmbeddedForm, KnownToolSpec, ToolCategory } from './extract/tools-table.js'
export { KNOWN_TOOLS, lookupTool } from './extract/tools-table.js'
// --- end extract ---

// --- policy: tiers, denylist, decisions (P1 Task 9) ---
export type { DecisionHints, GuardAnnotation, GuardTarget } from './policy/decisions.js'
export { askPrompt, formatDecision } from './policy/decisions.js'
export type { DenyEntry } from './policy/denylist.js'
export { checkDenylist, DENYLIST } from './policy/denylist.js'
export { ALWAYS_UNSKIPPABLE, effectiveTier, tierAllowed } from './policy/tiers.js'
// --- end policy ---

// --- policy: guard (P1 Task 11) ---
export { releaseHeldCall } from './audit/subscriber.js'
export type { GuardContext, GuardOutcome } from './policy/guard.js'
export {
  createScopeGuard,
  evaluateGuard,
  installScopeGuard,
  isScopeGuardInstalled,
  wasInspected,
} from './policy/guard.js'
export type { ProtectedHit, ProtectedScope } from './policy/protected-paths.js'
export { protectedCommandHit, protectedFileHit } from './policy/protected-paths.js'
export { isLocalTarget } from './scope/engine.js'
// --- end guard ---

// --- engagement-guard: host types, shell chain, case text ---
export { type CaseTextHints, renderCaseContext } from './engagement/render.js'
export type { ShellChain } from './shell/chain.js'
export { splitShellChain } from './shell/chain.js'
export * from './types.js'
// --- end engagement-guard ---
