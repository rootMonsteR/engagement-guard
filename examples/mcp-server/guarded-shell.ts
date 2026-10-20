import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import type { EventSource, Guard, GuardEvent, GuardOutcome } from 'engagement-guard'

/** `Omit` over each member of a union, not over the keys the members share. */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never

/** The events this example reports to the guard's audit log, with the `emit` the guard lacks. */
export interface ExecEvents extends EventSource {
  emit(e: DistributiveOmit<GuardEvent, 'ts'>): void
}

/** A tiny event source wired into `guard.subscribe`, so executions land in the audit chain. */
export function createExecEvents(guard: Guard): ExecEvents {
  const listeners = new Map<string, Set<(e: GuardEvent) => void>>()
  const events: ExecEvents = {
    on(type, fn) {
      let set = listeners.get(type)
      if (set === undefined) {
        set = new Set()
        listeners.set(type, set)
      }
      set.add(fn)
      return () => {
        set.delete(fn)
      }
    },
    emit(e) {
      const stamped = { ...e, ts: Date.now() } as GuardEvent
      for (const fn of listeners.get(e.type) ?? []) fn(stamped)
      for (const fn of listeners.get('*') ?? []) fn(stamped)
    },
  }
  guard.subscribe(events)
  return events
}

export interface GuardedShellInput {
  command: string
  cwd?: string
}

export type GuardedShellResult =
  | { ran: false; decision: GuardOutcome }
  | { ran: true; exitCode: number | null; stdout: string; stderr: string }

const DEFAULT_TAIL_BYTES = 8 * 1024

/** Keeps the last `max` bytes of what a stream produced. */
function tail(max: number): { push(chunk: Buffer): void; text(): string } {
  let buf = Buffer.alloc(0)
  return {
    push(chunk) {
      buf = Buffer.concat([buf, chunk])
      if (buf.length > max) buf = buf.subarray(buf.length - max)
    },
    text: () => buf.toString('utf8'),
  }
}

/**
 * Runs `command` through the platform shell only when the guard passes it (or does not inspect
 * it); a deny or an ask is returned as the decision and nothing runs. The spawn and the exit are
 * reported to the audit log through `events`.
 */
export async function guardedShell(
  guard: Guard,
  input: GuardedShellInput,
  events: ExecEvents,
  opts: { tailBytes?: number } = {},
): Promise<GuardedShellResult> {
  const cwd = input.cwd ?? guard.cases.cwd
  const toolUseId = `mcp_${randomUUID()}`
  const decision = await guard.check(input.command, { cwd, toolUseId })
  if (decision !== 'not-inspected' && decision.verdict !== 'pass') {
    return { ran: false, decision }
  }
  const execId = `exec_${randomUUID()}`
  const started = Date.now()
  events.emit({
    type: 'exec.spawn',
    execId,
    command: input.command,
    cwd,
    backend: 'local',
    toolUseId,
  })
  const [file, args] =
    process.platform === 'win32'
      ? ['cmd.exe', ['/d', '/s', '/c', input.command]]
      : ['/bin/sh', ['-c', input.command]]
  const out = tail(opts.tailBytes ?? DEFAULT_TAIL_BYTES)
  const err = tail(opts.tailBytes ?? DEFAULT_TAIL_BYTES)
  const exitCode = await new Promise<number | null>((resolve, reject) => {
    const child = spawn(file, args, { cwd, windowsVerbatimArguments: true })
    child.stdout.on('data', (chunk: Buffer) => out.push(chunk))
    child.stderr.on('data', (chunk: Buffer) => err.push(chunk))
    child.on('error', reject)
    child.on('close', (code) => resolve(code))
  })
  events.emit({
    type: 'exec.exit',
    execId,
    code: exitCode,
    timedOut: false,
    durationMs: Date.now() - started,
    toolUseId,
  })
  return { ran: true, exitCode, stdout: out.text(), stderr: err.text() }
}
