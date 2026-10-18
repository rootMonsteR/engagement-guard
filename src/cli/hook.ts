import { resolve } from 'node:path'
import type { Readable } from 'node:stream'
import { parseArgs } from 'node:util'
import { z } from 'zod'
import { messageOf } from '../audit/util.js'
import { createGuard, type Guard } from '../guard.js'
import type { GuardOutcome } from '../policy/guard.js'
import type { GuardRequest } from '../types.js'
import { guardOptions, writeLine } from './args.js'
import type { CliIo } from './main.js'

const USAGE =
  'Usage: engagement-guard hook [--tool <name>]... [--shell posix|powershell] [--timeout-ms <n>]'

/**
 * Claude Code's file tools and the `tool_input` field that names the file each one writes. They
 * are inspected by default, so the model cannot rewrite the case file, audit log or keys with them.
 */
const FILE_TOOL_PATH: ReadonlyMap<string, string> = new Map([
  ['Write', 'file_path'],
  ['Edit', 'file_path'],
  ['MultiEdit', 'file_path'],
  ['NotebookEdit', 'notebook_path'],
])

/** The tools inspected without any `--tool`: the shell tool and the file tools. */
export const DEFAULT_HOOK_TOOLS: readonly string[] = ['Bash', ...FILE_TOOL_PATH.keys()]

/** The overall deadline for a decision when `--timeout-ms` is not given. */
export const DEFAULT_HOOK_TIMEOUT_MS = 20_000

/** The largest delay `setTimeout` honours; anything above it would fire at once. */
const MAX_TIMEOUT_MS = 2_147_483_647

/** What the hook needs from Claude Code's `PreToolUse` JSON. */
export interface HookInput {
  toolName: string
  /** `tool_input.command`, when the payload carries one (absent, not `''`, when it does not). */
  command?: string
  /** The whole `tool_input`, so a non-shell tool is inspected by everything it was given. */
  input: Record<string, unknown>
  cwd: string
  sessionId: string
  toolUseId?: string
  /** `hook_event_name`, when the payload carries it. */
  event?: string
}

const HookJsonSchema = z.looseObject({
  hook_event_name: z.string().optional(),
  tool_name: z.string().min(1),
  tool_input: z.looseObject({ command: z.string().optional() }).optional(),
  cwd: z.string().min(1),
  session_id: z.string().min(1),
  tool_use_id: z.string().optional(),
})

/** Parses the hook's stdin; anything that is not the documented shape is an error (fail closed). */
export function parseHookInput(raw: string): HookInput | { error: string } {
  let obj: unknown
  try {
    obj = JSON.parse(raw)
  } catch (err) {
    return { error: `stdin is not JSON: ${messageOf(err)}` }
  }
  const parsed = HookJsonSchema.safeParse(obj)
  if (!parsed.success) {
    return {
      error: `stdin is not a PreToolUse payload: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`,
    }
  }
  const v = parsed.data
  return {
    toolName: v.tool_name,
    ...(v.tool_input?.command === undefined ? {} : { command: v.tool_input.command }),
    input: v.tool_input ?? {},
    cwd: v.cwd,
    sessionId: v.session_id,
    ...(v.tool_use_id === undefined ? {} : { toolUseId: v.tool_use_id }),
    ...(v.hook_event_name === undefined ? {} : { event: v.hook_event_name }),
  }
}

const UNSKIPPABLE_PREFIX = '[cannot be auto-approved] '

function hookJson(permissionDecision: 'deny' | 'ask', reason: string): string {
  return JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision,
      permissionDecisionReason: reason,
    },
  })
}

/**
 * The hook's stdout for a decision (spec §7): `deny` and `ask` are forwarded with the decision
 * text as the reason. Claude Code's `ask` forces a prompt even in auto mode, but the hook cannot
 * mark it unskippable, so an unskippable ask carries a prefix that says so. Pass, quiet and
 * not-inspected print nothing, so the harness's ordinary permission flow applies.
 */
export function hookOutput(outcome: GuardOutcome | 'not-inspected'): string | undefined {
  if (outcome === 'not-inspected' || outcome.quiet === true) return undefined
  switch (outcome.verdict) {
    case 'deny':
      return hookJson('deny', outcome.message)
    case 'ask':
      return hookJson('ask', outcome.message)
    case 'ask-unskippable':
      return hookJson('ask', `${UNSKIPPABLE_PREFIX}${outcome.message}`)
    default:
      return undefined
  }
}

async function readAll(stdin: Readable): Promise<string> {
  let buf = ''
  for await (const chunk of stdin) {
    buf += typeof chunk === 'string' ? chunk : (chunk as Buffer).toString('utf8')
  }
  return buf
}

/**
 * The request the guard sees for a hook call, or an error when the payload lacks what the tool
 * needs (fail closed: a renamed field must not let every call through). `Bash` is analysed as
 * shell text and must carry a string `command` (its rule key). A file tool is a write-class call
 * whose rule key is the file it writes, resolved against the hook's `cwd`; it must carry a string
 * path. Any other inspected tool is a network-class call whose whole input the guard sweeps for
 * targets, since only the harness knows what the tool does with them.
 */
export function hookRequest(input: HookInput): GuardRequest | { error: string } {
  const base = {
    toolName: input.toolName,
    input: input.input,
    cwd: input.cwd,
    sessionId: input.sessionId,
    depth: 0,
    ...(input.toolUseId === undefined ? {} : { toolUseId: input.toolUseId }),
  }
  const pathField = FILE_TOOL_PATH.get(input.toolName)
  if (pathField !== undefined) {
    const raw = input.input[pathField]
    if (typeof raw !== 'string' || raw === '') {
      return { error: `${input.toolName} payload has no string tool_input.${pathField}` }
    }
    const file = resolve(input.cwd, raw)
    return {
      ...base,
      ruleKey: file,
      permissionClass: 'write',
      summary: `${input.toolName} ${file}`,
    }
  }
  if (input.toolName === 'Bash') {
    if (input.command === undefined) {
      return { error: 'Bash payload has no string tool_input.command' }
    }
    return { ...base, ruleKey: input.command, permissionClass: 'exec', summary: input.command }
  }
  const summary =
    input.command === undefined || input.command === '' ? input.toolName : input.command
  return { ...base, ruleKey: input.toolName, permissionClass: 'network', summary }
}

/**
 * Nothing could be decided, so nothing may run: the deny JSON on stdout for the structured path,
 * and the reason on stderr with exit 2, which blocks on its own even if the JSON is not read
 * (Claude Code: "If your hook is meant to enforce a policy, use exit 2").
 */
function failClosed(io: CliIo, reason: string): number {
  const text = `GUARD_ERROR: ${reason}`
  writeLine(io.stdout, hookJson('deny', text))
  writeLine(io.stderr, text)
  return 2
}

/** What a decision came to: the stdout line to print (if any), or why it could not be made. */
type HookResult = { out: string | undefined } | { error: string }

/** Shared between the decision and its deadline, so a guard opened too late is closed at once. */
interface DecisionState {
  guard?: Guard
  late: boolean
}

function disposeQuietly(guard: Guard): void {
  guard.dispose().catch(() => {})
}

/** Reads the payload and decides it. Writes nothing: the caller prints whichever result wins. */
async function decide(
  io: CliIo,
  tools: readonly string[],
  shell: 'posix' | 'powershell',
  state: DecisionState,
): Promise<HookResult> {
  const input = parseHookInput(await readAll(io.stdin))
  if ('error' in input) return input
  if (input.event !== undefined && input.event !== 'PreToolUse') return { out: undefined }
  if (!tools.includes(input.toolName)) return { out: undefined }
  const req = hookRequest(input)
  if ('error' in req) return req
  const project = io.env.CLAUDE_PROJECT_DIR?.trim()
  const workspace = project !== undefined && project !== '' ? project : input.cwd
  const guard = await createGuard(
    guardOptions(io, { cwd: workspace, sessionId: input.sessionId, shell }),
  )
  if (state.late) {
    disposeQuietly(guard)
    return { error: 'decision abandoned after the deadline' }
  }
  state.guard = guard
  try {
    return { out: hookOutput(await guard.checkRequest(req)) }
  } finally {
    await guard.dispose()
  }
}

/**
 * Claude Code `PreToolUse` adapter: reads the hook JSON on stdin, decides the call with a guard
 * over the project (`CLAUDE_PROJECT_DIR`, else the hook's `cwd`), prints the decision JSON (or
 * nothing for a pass) and exits 0. `Bash` and the file tools (`Write`, `Edit`, `MultiEdit`,
 * `NotebookEdit`) are inspected by default; `--tool` adds others. A payload for another event, or
 * a tool outside the inspected set, prints nothing. Any failure on the way to a decision fails
 * closed (spec D12), because Claude Code treats a crashed hook as non-blocking and would
 * otherwise run the command; so does a decision that outlives `--timeout-ms` (default 20 s),
 * because Claude Code treats a timed-out hook as non-blocking too.
 */
export async function runHook(args: string[], io: CliIo): Promise<number> {
  let tools: string[]
  let shell: 'posix' | 'powershell'
  let timeoutMs: number
  try {
    const { values } = parseArgs({
      args,
      options: {
        tool: { type: 'string', multiple: true },
        shell: { type: 'string' },
        'timeout-ms': { type: 'string' },
      },
      allowPositionals: false,
      strict: true,
    })
    tools = [...DEFAULT_HOOK_TOOLS, ...(values.tool ?? [])]
    if (values.shell !== undefined && values.shell !== 'posix' && values.shell !== 'powershell') {
      throw new Error(`--shell must be posix or powershell, not '${values.shell}'`)
    }
    shell = values.shell ?? 'posix'
    const t = values['timeout-ms']
    timeoutMs = t === undefined ? DEFAULT_HOOK_TIMEOUT_MS : Number(t)
    if (t !== undefined && (!/^[1-9][0-9]*$/.test(t) || timeoutMs > MAX_TIMEOUT_MS)) {
      throw new Error(`--timeout-ms must be a whole number from 1 to ${MAX_TIMEOUT_MS}, not '${t}'`)
    }
  } catch (err) {
    writeLine(io.stderr, USAGE)
    return failClosed(io, messageOf(err))
  }

  const state: DecisionState = { late: false }
  const work = decide(io, tools, shell, state).catch(
    (err: unknown): HookResult => ({ error: messageOf(err) }),
  )
  let timer: ReturnType<typeof setTimeout> | undefined
  const deadline = new Promise<'timeout'>((done) => {
    timer = setTimeout(() => done('timeout'), timeoutMs)
  })
  let result: HookResult | 'timeout'
  try {
    result = await Promise.race([work, deadline])
  } finally {
    clearTimeout(timer)
  }
  if (result === 'timeout') {
    // Best effort: the guard may be stuck mid-decision, so its dispose is not waited for.
    state.late = true
    if (state.guard !== undefined) disposeQuietly(state.guard)
    return failClosed(io, `decision timed out after ${timeoutMs} ms`)
  }
  if ('error' in result) return failClosed(io, result.error)
  if (result.out !== undefined) writeLine(io.stdout, result.out)
  return 0
}
