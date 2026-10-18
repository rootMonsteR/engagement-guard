import { randomBytes } from 'node:crypto'
import { mkdir, rename, rm, stat } from 'node:fs/promises'
import { join } from 'node:path'

/** Thrown when the lock could not be taken within `timeoutMs`. */
export class LockTimeoutError extends Error {
  constructor(dir: string) {
    super(`audit chain lock timed out: ${dir}`)
    this.name = 'LockTimeoutError'
  }
}

const LOCK_NAME = '.lock'
const DEFAULT_TIMEOUT_MS = 5_000
const DEFAULT_STALE_MS = 30_000

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms))

const isExists = (err: unknown): boolean =>
  typeof err === 'object' && err !== null && (err as NodeJS.ErrnoException).code === 'EEXIST'

const isNotFound = (err: unknown): boolean =>
  typeof err === 'object' && err !== null && (err as NodeJS.ErrnoException).code === 'ENOENT'

/** True when the lock directory exists and its mtime is older than `staleMs`. */
async function isStale(lock: string, staleMs: number): Promise<boolean> {
  try {
    const st = await stat(lock)
    return Date.now() - st.mtimeMs > staleMs
  } catch (err) {
    if (isNotFound(err)) return false
    throw err
  }
}

/**
 * Takes over the stale lock `lock` without racing another waiter: the lock directory is first
 * renamed to a unique `<lock>.stale-<pid>-<random>`, an atomic step only one waiter can win (the
 * others see ENOENT). The renamed directory is checked again: if it is no longer stale, a new
 * holder took the lock between the caller's stale check and the rename, so it is put back and
 * nothing is taken over. Returns true when a stale lock was removed and the caller should retry
 * at once; false when the caller should simply keep waiting.
 */
export async function takeOverStaleLock(lock: string, staleMs: number): Promise<boolean> {
  const moved = `${lock}.stale-${process.pid}-${randomBytes(6).toString('hex')}`
  try {
    await rename(lock, moved)
  } catch (err) {
    if (isNotFound(err)) return false
    throw err
  }
  if (!(await isStale(moved, staleMs))) {
    // A live holder's lock: give it back (on failure its holder has lost the lock, as before).
    await rename(moved, lock).catch(() => rm(moved, { recursive: true, force: true }))
    return false
  }
  await rm(moved, { recursive: true, force: true })
  return true
}

/**
 * Runs `fn` while holding `<dir>/.lock`, so that several processes appending to one audit chain
 * (spec §4.3: parallel Claude Code hooks) take turns. `mkdir` of the lock directory is the atomic
 * acquire on every platform; a holder retries every 10–40 ms (jittered) until `timeoutMs`
 * (default 5 s) and then throws `LockTimeoutError`; a lock whose mtime is older than `staleMs`
 * (default 30 s) is treated as abandoned by a dead process and taken over (renamed away first, so
 * only one waiter takes over a given stale lock: `takeOverStaleLock`). The caller's own lock
 * is always removed, whether `fn` resolves or rejects. `dir` is created when missing.
 *
 * Limit: the lock's mtime is set once, at acquisition, so a holder that keeps the lock longer
 * than `staleMs` can lose it to a waiter. Audit appends hold it for milliseconds.
 */
export async function withChainLock<T>(
  dir: string,
  fn: () => Promise<T>,
  opts: { timeoutMs?: number; staleMs?: number } = {},
): Promise<T> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const staleMs = opts.staleMs ?? DEFAULT_STALE_MS
  const lock = join(dir, LOCK_NAME)
  await mkdir(dir, { recursive: true })
  const deadline = Date.now() + timeoutMs
  for (;;) {
    try {
      await mkdir(lock)
      break
    } catch (err) {
      if (!isExists(err)) throw err
    }
    if ((await isStale(lock, staleMs)) && (await takeOverStaleLock(lock, staleMs))) continue
    if (Date.now() >= deadline) throw new LockTimeoutError(dir)
    await sleep(10 + Math.random() * 30)
  }
  try {
    return await fn()
  } finally {
    await rm(lock, { recursive: true, force: true })
  }
}
