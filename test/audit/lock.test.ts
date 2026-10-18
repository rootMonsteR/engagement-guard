import { access, mkdir, mkdtemp, readdir, rm, utimes } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { LockTimeoutError, takeOverStaleLock, withChainLock } from '../../src/audit/lock.js'

let dir: string

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'guard-lock-'))
})

afterEach(async () => {
  await rm(dir, { recursive: true, force: true })
})

const exists = (p: string) =>
  access(p).then(
    () => true,
    () => false,
  )

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

describe('withChainLock', () => {
  it('serialises two holders', async () => {
    const order: string[] = []
    const hold = (name: string) =>
      withChainLock(dir, async () => {
        order.push(`${name}-in`)
        await sleep(30)
        order.push(`${name}-out`)
      })
    const first = hold('a')
    while (!order.includes('a-in')) await sleep(1)
    await Promise.all([first, hold('b')])
    expect(order).toEqual(['a-in', 'a-out', 'b-in', 'b-out'])
  })

  it('returns what the function returns and creates the directory', async () => {
    const nested = join(dir, 'case', 'chain')
    expect(await withChainLock(nested, async () => 42)).toBe(42)
    expect(await exists(nested)).toBe(true)
  })

  it('takes over a stale lock', async () => {
    const lock = join(dir, '.lock')
    await mkdir(lock)
    const past = new Date(Date.now() - 60_000)
    await utimes(lock, past, past)
    const started = Date.now()
    expect(await withChainLock(dir, async () => 'ok')).toBe('ok')
    expect(Date.now() - started).toBeLessThan(1000)
  })

  it('times out on a fresh foreign lock', async () => {
    await mkdir(join(dir, '.lock'))
    await expect(
      withChainLock(dir, async () => 'never', { timeoutMs: 200 }),
    ).rejects.toBeInstanceOf(LockTimeoutError)
  })

  it('always removes its own lock', async () => {
    await expect(
      withChainLock(dir, async () => {
        throw new Error('boom')
      }),
    ).rejects.toThrow('boom')
    expect(await exists(join(dir, '.lock'))).toBe(false)
  })

  it('two waiters on one stale lock: exactly one takes it over and they still serialise', async () => {
    const lock = join(dir, '.lock')
    for (let round = 0; round < 10; round++) {
      await mkdir(lock)
      const past = new Date(Date.now() - 60_000)
      await utimes(lock, past, past)
      const order: string[] = []
      let inside = 0
      let overlap = false
      const hold = (name: string) =>
        withChainLock(dir, async () => {
          inside++
          if (inside > 1) overlap = true
          order.push(`${name}-in`)
          await sleep(20)
          order.push(`${name}-out`)
          inside--
        })
      await Promise.all([hold('a'), hold('b')])
      expect(overlap).toBe(false)
      expect(order).toHaveLength(4)
      expect(order[1]).toBe(`${order[0]?.slice(0, 1)}-out`)
      // No renamed stale lock is left behind.
      expect((await readdir(dir)).filter((n) => n.startsWith('.lock'))).toEqual([])
    }
  })
})

describe('takeOverStaleLock', () => {
  it('renames a stale lock away, removes it and reports the takeover', async () => {
    const lock = join(dir, '.lock')
    await mkdir(lock)
    const past = new Date(Date.now() - 60_000)
    await utimes(lock, past, past)
    expect(await takeOverStaleLock(lock, 30_000)).toBe(true)
    expect(await readdir(dir)).toEqual([])
  })

  it('reports false when another waiter already took the lock over (ENOENT)', async () => {
    expect(await takeOverStaleLock(join(dir, '.lock'), 30_000)).toBe(false)
  })

  it('puts back a lock that turned out to be fresh (a new holder raced in) and reports false', async () => {
    const lock = join(dir, '.lock')
    await mkdir(lock)
    expect(await takeOverStaleLock(lock, 30_000)).toBe(false)
    expect(await exists(lock)).toBe(true)
    expect(await readdir(dir)).toEqual(['.lock'])
  })
})
