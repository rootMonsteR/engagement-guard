import { PassThrough } from 'node:stream'
import type { CliIo } from '../../src/cli/main.js'
import type { LookupFn } from '../../src/scope/resolver.js'

export interface TestCliIo extends CliIo {
  /** Everything written to stdout so far. */
  out(): string
  /** Everything written to stderr so far. */
  err(): string
}

/**
 * A `CliIo` over in-memory streams: `stdin` holds `opts.stdin` (default empty) and is ended.
 * `tty` (default true) says whether stdin and stdout are a terminal; pass false for an agent.
 */
export function createCliIo(opts: {
  cwd: string
  env?: NodeJS.ProcessEnv
  stdin?: string
  now?: () => Date
  lookup?: LookupFn
  tty?: boolean
}): TestCliIo {
  const stdin = new PassThrough()
  stdin.end(opts.stdin ?? '')
  let out = ''
  let err = ''
  const stdout = new PassThrough()
  stdout.on('data', (chunk: Buffer | string) => {
    out += chunk.toString()
  })
  const stderr = new PassThrough()
  stderr.on('data', (chunk: Buffer | string) => {
    err += chunk.toString()
  })
  return {
    stdin,
    stdout,
    stderr,
    cwd: opts.cwd,
    env: opts.env ?? {},
    tty: opts.tty ?? true,
    ...(opts.now === undefined ? {} : { now: opts.now }),
    ...(opts.lookup === undefined ? {} : { lookup: opts.lookup }),
    out: () => out,
    err: () => err,
  }
}
