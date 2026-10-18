import type { Decision, GuardHost, GuardRequest, Middleware } from '../../src/types.js'

export type FakeMode = 'default' | 'unrestricted' | 'read-only'

/**
 * A stand-in for an agent harness's permission engine: middlewares installed with `use`, a core
 * decision by mode (or a fixed one), and a record of grants. It applies no rules of its own.
 */
export interface FakeHost extends GuardHost {
  /**
   * Runs the `before-rules` middlewares (install order, each wrapping the next) around the
   * `after-rules` middlewares (install order) around the core decision.
   */
  evaluate(req: GuardRequest): Promise<Decision>
  /** Records the grant; in default mode a granted `Bash(<program>:*)` or `Bash` rule makes the core allow. */
  grant(rule: string, scope: 'session' | 'turn'): void
  grants: string[]
  mode: FakeMode
}

function coreByMode(mode: FakeMode, req: GuardRequest, grants: readonly string[]): Decision {
  if (mode === 'read-only' && req.permissionClass !== 'read') {
    return { kind: 'deny', reason: 'read-only mode', source: 'mode' }
  }
  if (mode === 'default' && req.toolName === 'Bash') {
    const program = req.ruleKey.trim().split(/\s+/)[0] ?? ''
    if (grants.includes(`Bash(${program}:*)`) || grants.includes('Bash')) {
      return { kind: 'allow', reason: 'granted', source: 'session' }
    }
    return {
      kind: 'ask',
      prompt: { title: req.summary, allowAlwaysRule: `Bash(${program}:*)` },
      source: 'rule',
    }
  }
  return { kind: 'allow', reason: 'mode', source: 'mode' }
}

export function createFakeHost(
  opts: { mode?: FakeMode; core?: Decision | ((req: GuardRequest) => Decision) } = {},
): FakeHost {
  const stages: Record<'before-rules' | 'after-rules', { mw: Middleware }[]> = {
    'before-rules': [],
    'after-rules': [],
  }
  const core = (req: GuardRequest): Decision => {
    if (opts.core === undefined) return coreByMode(host.mode, req, host.grants)
    return typeof opts.core === 'function' ? opts.core(req) : opts.core
  }
  const host: FakeHost = {
    mode: opts.mode ?? 'default',
    grants: [],
    use(mw, stage) {
      const entry = { mw }
      stages[stage].push(entry)
      return () => {
        const list = stages[stage]
        const i = list.indexOf(entry)
        if (i !== -1) list.splice(i, 1)
      }
    },
    grant(rule) {
      host.grants.push(rule)
    },
    evaluate(req) {
      const chain = [...stages['before-rules'], ...stages['after-rules']].map((e) => e.mw)
      const run = async (i: number): Promise<Decision> => {
        const mw = chain[i]
        return mw === undefined ? core(req) : mw(req, () => run(i + 1))
      }
      return run(0)
    },
  }
  return host
}
