export type PermissionClass = 'read' | 'write' | 'exec' | 'network' | 'destructive'
export interface GuardRequest {
  toolName: string
  input: unknown
  /** For shell tools, the command text; otherwise the harness's rule key. */
  ruleKey: string
  permissionClass: PermissionClass
  summary: string
  cwd: string
  sessionId: string
  depth: number
  toolUseId?: string
}
export type DecisionSource = 'blocklist' | 'rule' | 'mode' | 'session' | 'plugin' | 'user'
export type Decision =
  | {
      kind: 'allow' | 'deny'
      reason: string
      source: DecisionSource
      annotations?: Record<string, unknown>
    }
  | {
      kind: 'ask'
      prompt: { title: string; detail?: string; allowAlwaysRule?: string }
      unskippable?: boolean
      source: DecisionSource
      annotations?: Record<string, unknown>
    }
export type Middleware = (req: GuardRequest, next: () => Promise<Decision>) => Promise<Decision>
export interface GuardHost {
  use(mw: Middleware, stage: 'before-rules' | 'after-rules'): () => void
}
export interface Prompter {
  askUser(q: { question: string; options?: string[] }): Promise<string>
}
export interface OutputDigest {
  sha256: string
  bytes: number
}
export type GuardEvent = { ts: number } & (
  | { type: 'session.start'; sessionId: string; cwd: string; model: string }
  | { type: 'session.end'; sessionId: string }
  | { type: 'turn.end'; turnId: string; stopReason: string; steps: number }
  | { type: 'tool.call'; toolUseId: string; name: string; input: unknown; summary: string }
  | { type: 'permission.decision'; toolUseId: string; decision: Decision }
  | {
      type: 'exec.spawn'
      execId: string
      command: string
      cwd: string
      backend: string
      toolUseId?: string
    }
  | {
      type: 'exec.exit'
      execId: string
      code: number | null
      timedOut: boolean
      durationMs: number
      toolUseId?: string
      output?: { stdout: OutputDigest; stderr: OutputDigest }
    }
  | {
      type: 'tool.result'
      toolUseId: string
      name: string
      isError: boolean
      durationMs: number
      content: string
    }
)
export interface EventSource {
  on(type: GuardEvent['type'] | '*', fn: (e: GuardEvent) => void): () => void
}
