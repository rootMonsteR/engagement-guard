import { randomUUID } from 'node:crypto'
import { stat } from 'node:fs/promises'
import { join } from 'node:path'
import { subscribeAudit } from './audit/subscriber.js'
import { type AuditLog, createAuditLog, NO_CASE } from './audit/writer.js'
import { type CommandOutcome, runEngagementCommand } from './engagement/commands.js'
import type { LoadedCase } from './engagement/load.js'
import { type CaseState, type CaseStore, createCaseStore } from './engagement/store.js'
import { createTargetExtractor } from './extract/extractor.js'
import { resolveOperator } from './first-run.js'
import { type GuardPaths, resolvePaths } from './paths.js'
import { formatDecision, type GuardAnnotation } from './policy/decisions.js'
import {
  createScopeGuard,
  type GuardOutcome,
  installScopeGuard,
  wasInspected,
} from './policy/guard.js'
import { createScopeEngine, type ScopeEngine } from './scope/engine.js'
import { createResolver, type LookupFn } from './scope/resolver.js'
import { compileTrustedInfra } from './scope/trusted-infra.js'
import type {
  Decision,
  EventSource,
  GuardHost,
  GuardRequest,
  Middleware,
  Prompter,
} from './types.js'

export interface CreateGuardOptions {
  /** The workspace root: `<dirName>/engagement.yaml` and `<dirName>/audit/` live under it. */
  cwd: string
  /** The home holding the first-run acknowledgement and the signing key; default `GUARD_HOME` or `~/.engagement-guard`. */
  home?: string
  /** The workspace directory name; default `.guard`. */
  dirName?: string
  /** The command named in decisions that attest a scope change; default `engagement-guard engagement edit`. */
  commandHint?: string
  /** The audit session; default a random UUID. */
  sessionId?: string
  /** How shell commands are parsed; default `posix` (Claude Code's Bash tool runs Git Bash on Windows). */
  shell?: 'posix' | 'powershell'
  /** DNS lookup for the resolver (tests inject a fake); default the system resolver. */
  lookup?: LookupFn
  now?: () => Date
  /** The only environment read (`GUARD_HOME`, `GUARD_OPERATOR`); default none. */
  env?: NodeJS.ProcessEnv
  /** Take the per-case audit lock around every append (several processes on one chain); default off. */
  lock?: boolean
  /** The operator recorded on audit records; default `GUARD_OPERATOR` or the OS user. */
  operator?: string
}

export interface Guard {
  readonly paths: GuardPaths
  readonly cases: CaseStore
  readonly audit: AuditLog
  /**
   * The guard's decision for a shell command, audited: the CLI, the hook and the MCP example call
   * this. Rejects with `guard disposed` after `dispose()`.
   */
  check(
    command: string,
    opts?: { cwd?: string; toolUseId?: string },
  ): Promise<GuardOutcome | 'not-inspected'>
  /** The same decision for any request, structured network tools included; rejects after `dispose()`. */
  checkRequest(req: GuardRequest): Promise<GuardOutcome | 'not-inspected'>
  /** The `before-rules` middleware for a harness with a permission engine. */
  readonly middleware: Middleware
  /** Installs the middleware on a host; returns the remover. `dispose` removes it too. */
  install(host: GuardHost): () => void
  /** Routes a harness's events (`exec.spawn`, `exec.exit`, `tool.result`, …) into the audit log. */
  subscribe(events: EventSource): () => void
  /** `engagement <sub>` against this guard's case store and audit log. */
  engagement(
    argv: string[],
    io?: { prompter?: Prompter; interactive?: boolean },
  ): Promise<CommandOutcome>
  /** Removes every middleware and subscription and flushes the audit log. Idempotent. */
  dispose(): Promise<void>
}

/**
 * What `check`/`checkRequest` hand the middleware as the host's decision: none is known, the
 * caller (CLI, hook, MCP server) maps the guard's own verdict, and a human may still be asked.
 * So the `permission` record says the decision was delegated, never that it was allowed.
 */
const DELEGATED: Decision = {
  kind: 'ask',
  prompt: { title: 'decision delegated to the caller' },
  source: 'plugin',
}

/** The case a state carries (unacknowledged, tampered, active), if any. */
const caseOf = (s: CaseState): LoadedCase | undefined => ('case' in s ? s.case : undefined)

/**
 * One guard over one workspace (spec §5): the audit log, the case store (initial load), the
 * extractor, trusted list and resolver (consulted only by the scope engine of an active case),
 * the scope guard middleware, and the case-change handler that re-points the audit log and drops
 * the scope engine of the old case. If a step fails, the steps already taken are undone and the
 * error is thrown: a caller must not run without the guard it asked for.
 */
export async function createGuard(opts: CreateGuardOptions): Promise<Guard> {
  const { cwd } = opts
  const workspace = await stat(cwd).catch(() => undefined)
  if (workspace === undefined || !workspace.isDirectory()) {
    throw new Error(`workspace is not a directory: ${cwd}`)
  }
  const env = opts.env ?? {}
  const now = opts.now ?? (() => new Date())
  const paths = resolvePaths({
    env,
    ...(opts.home === undefined ? {} : { home: opts.home }),
    ...(opts.dirName === undefined ? {} : { dirName: opts.dirName }),
    ...(opts.commandHint === undefined ? {} : { commandHint: opts.commandHint }),
  })
  const sessionId = opts.sessionId ?? randomUUID()

  // 1. The audit log of this session (chains are created lazily by the first record).
  const audit = createAuditLog({
    dir: join(cwd, ...paths.auditDir.split('/')),
    sessionId,
    operator: opts.operator ?? resolveOperator(env),
    now,
    lock: opts.lock === true,
  })

  const undo: (() => void)[] = []
  let cases: CaseStore
  let middleware: Middleware
  try {
    // 2. The case store; its initial reload records `case.activate` for an active case.
    cases = await createCaseStore({
      cwd,
      home: paths.home,
      audit,
      now,
      engagementPath: paths.engagementPath,
      casesDir: paths.casesDir,
    })

    const pointAudit = (s: CaseState): void => {
      audit.setCase(caseOf(s)?.engagement.id ?? NO_CASE)
    }
    pointAudit(cases.state())

    // 3. Static inputs of the guard; only the scope engine of an active case consults the resolver.
    const extractor = createTargetExtractor()
    const trusted = compileTrustedInfra()
    const resolver = createResolver(opts.lookup === undefined ? {} : { lookup: opts.lookup })
    let engine: { case: LoadedCase; engine: ScopeEngine } | undefined
    const scope = (): ScopeEngine | undefined => {
      const s = cases.state()
      if (s.status !== 'active') return undefined
      if (engine?.case !== s.case) {
        engine = { case: s.case, engine: createScopeEngine({ case: s.case, resolver, trusted }) }
      }
      return engine.engine
    }

    // 4. The guard.
    middleware = createScopeGuard({
      caseState: () => cases.state(),
      scope,
      extractor,
      trusted,
      audit,
      now,
      shell: opts.shell ?? 'posix',
      paths,
      workspace: cwd,
    })

    // 5. Case changes: re-point the audit log and drop the scope engine of the old case.
    undo.push(
      cases.onChange((s) => {
        engine = undefined
        pointAudit(s)
      }),
    )
    pointAudit(cases.state())
  } catch (err) {
    for (const off of undo.reverse()) off()
    await audit.flush()
    throw err
  }

  /** The case file a decision names, as the guard itself resolves it. */
  const casePath = (): string => {
    const s = cases.state()
    if ('case' in s) return s.case.path
    if (s.status === 'invalid') return s.path
    return join(cwd, paths.engagementPath)
  }

  let disposed: Promise<void> | undefined

  async function checkRequest(req: GuardRequest): Promise<GuardOutcome | 'not-inspected'> {
    if (disposed !== undefined) throw new Error('guard disposed')
    const d = await middleware(req, async () => DELEGATED)
    const a = d.annotations?.guard as GuardAnnotation | undefined
    if (a === undefined) return 'not-inspected'
    return {
      verdict: a.verdict,
      reason: a.reason,
      annotation: a,
      message: formatDecision(a, {
        casePath: casePath(),
        engagementPath: paths.engagementPath,
        commandHint: paths.commandHint,
      }),
    }
  }

  return {
    paths,
    cases,
    audit,
    middleware,
    async check(command, o = {}) {
      const req: GuardRequest = {
        toolName: 'Bash',
        input: { command },
        ruleKey: command,
        permissionClass: 'exec',
        summary: command,
        cwd: o.cwd ?? cwd,
        sessionId,
        depth: 0,
        ...(o.toolUseId === undefined ? {} : { toolUseId: o.toolUseId }),
      }
      return checkRequest(req)
    },
    checkRequest,
    install(host) {
      const off = installScopeGuard(host, middleware)
      undo.push(off)
      return off
    },
    subscribe(events) {
      const off = subscribeAudit(events, audit, {
        caseActive: () => cases.state().status === 'active',
        inspected: wasInspected,
      })
      undo.push(off)
      return off
    },
    async engagement(argv, io = {}) {
      if (disposed !== undefined) {
        return { exitCode: 1, output: 'engagement: this guard is closed' }
      }
      return runEngagementCommand(argv, {
        cwd,
        home: paths.home,
        audit,
        cases,
        paths,
        interactive: io.interactive === true,
        now,
        ...(io.prompter === undefined ? {} : { ui: io.prompter }),
      })
    },
    dispose() {
      disposed ??= (async () => {
        for (const off of [...undo].reverse()) {
          try {
            off()
          } catch {
            // keep removing the rest
          }
        }
        await audit.flush()
      })()
      return disposed
    },
  }
}
