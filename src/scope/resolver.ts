import dns from 'node:dns'
import { normaliseHostname } from './hostname.js'
import { type IpAddr, parseIp } from './ip.js'

/** Forward lookup of every address of a name (A and AAAA). */
export type LookupFn = (host: string) => Promise<{ address: string; family: 4 | 6 }[]>

export type ResolveResult = { ok: true; ips: IpAddr[] } | { ok: false; error: string }

export interface Resolver {
  /**
   * Forward-resolves a hostname. Never throws: a failed or timed-out lookup, an empty answer or an
   * address that does not parse is `{ ok: false }`. Successful answers are cached for at most
   * 10 minutes (§6.3) and concurrent calls for one name share a single lookup. Reverse (PTR)
   * lookups are never made.
   */
  resolve(host: string): Promise<ResolveResult>
  /** Records `ips` as forward-confirmed addresses of the in-scope name `name`. */
  recordDerived(name: string, ips: IpAddr[]): void
  /** The in-scope name `ip` was derived from, while that resolution is still cached. */
  derivedFrom(ip: IpAddr): string | undefined
}

/** Upper bound on how long a resolution (and anything derived from it) is trusted (§6.3). */
export const MAX_DNS_TTL_MS = 600_000
/** How long one lookup may take before it counts as failed; a hung lookup never stalls a name. */
export const DEFAULT_LOOKUP_TIMEOUT_MS = 5_000
/** Default bound on the cache and on the derived-IP set (each). */
export const DEFAULT_MAX_ENTRIES = 4_096

// Read at call time so the module never holds its own reference to the real resolver.
const systemLookup: LookupFn = async (host) => {
  const answers = await dns.promises.lookup(host, { all: true })
  return answers.map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 }))
}

const MAPPED_TAG = 0xffffn

/** Map key for an address; a hand-built family-6 IPv4-mapped value keys as its IPv4 address. */
function keyOf(ip: IpAddr): string {
  if (ip.family === 6 && ip.value >> 32n === MAPPED_TAG) return `4:${ip.value & 0xffff_ffffn}`
  return `${ip.family}:${ip.value}`
}

/** An address from `getaddrinfo`, with any IPv6 zone id (`fe80::1%eth0`) removed. */
function parseAnswer(address: string): IpAddr | undefined {
  const zone = address.indexOf('%')
  return parseIp(zone >= 0 && address.includes(':') ? address.slice(0, zone) : address)
}

function clampTtl(ttlMs: number | undefined): number {
  if (ttlMs === undefined || Number.isNaN(ttlMs)) return MAX_DNS_TTL_MS
  return Math.min(Math.max(ttlMs, 0), MAX_DNS_TTL_MS)
}

/** `value` when it is a positive finite number, otherwise `fallback`. */
const positiveOr = (value: number | undefined, fallback: number) =>
  value !== undefined && Number.isFinite(value) && value > 0 ? value : fallback

/** Rejects when `p` has not settled within `ms`; the timer never keeps the process alive. */
function withTimeout<T>(p: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), ms)
    timer.unref?.()
    p.then(
      (value) => {
        clearTimeout(timer)
        resolve(value)
      },
      (err: unknown) => {
        clearTimeout(timer)
        reject(err)
      },
    )
  })
}

export function createResolver(opts?: {
  lookup?: LookupFn
  ttlMs?: number
  now?: () => number
  /** Per-lookup timeout (default 5 s); a lookup that takes longer resolves to `{ ok: false }`. */
  timeoutMs?: number
  /** Bound on cached names and on derived addresses, each (default 4096). */
  maxEntries?: number
}): Resolver {
  const lookup = opts?.lookup ?? systemLookup
  const ttlMs = clampTtl(opts?.ttlMs)
  const now = opts?.now ?? Date.now
  const timeoutMs = positiveOr(opts?.timeoutMs, DEFAULT_LOOKUP_TIMEOUT_MS)
  const maxEntries = Math.floor(positiveOr(opts?.maxEntries, DEFAULT_MAX_ENTRIES))

  const cache = new Map<string, { expires: number; ips: IpAddr[] }>()
  const inflight = new Map<string, Promise<ResolveResult>>()
  const derived = new Map<string, { name: string; expires: number }>()

  /** Inserts as the newest entry; when full, drops expired entries first, then the oldest. */
  function insertBounded<V extends { expires: number }>(
    map: Map<string, V>,
    key: string,
    value: V,
  ): void {
    map.delete(key)
    if (map.size >= maxEntries) {
      const t = now()
      for (const [k, v] of map) if (t >= v.expires) map.delete(k)
    }
    while (map.size >= maxEntries) {
      const oldest = map.keys().next()
      if (oldest.done) break
      map.delete(oldest.value)
    }
    map.set(key, value)
  }

  async function lookupOnce(name: string): Promise<ResolveResult> {
    let answers: { address: string }[]
    try {
      answers = await withTimeout(
        lookup(name),
        timeoutMs,
        `lookup of ${name} timed out after ${timeoutMs} ms`,
      )
    } catch (err) {
      return { ok: false, error: err instanceof Error ? err.message : String(err) }
    }
    if (!Array.isArray(answers) || answers.length === 0) {
      return { ok: false, error: `${name} has no addresses` }
    }
    const ips: IpAddr[] = []
    const seen = new Set<string>()
    for (const answer of answers) {
      const ip = parseAnswer(String(answer?.address))
      // One unreadable address could be the one that matters, so the whole answer is refused.
      if (ip === undefined) {
        return { ok: false, error: `${name} resolved to an unparseable address` }
      }
      const key = keyOf(ip)
      if (seen.has(key)) continue
      seen.add(key)
      ips.push(ip)
    }
    if (ttlMs > 0) insertBounded(cache, name, { expires: now() + ttlMs, ips })
    return { ok: true, ips: [...ips] }
  }

  return {
    resolve(host) {
      const name = normaliseHostname(host)
      if (name === undefined) {
        return Promise.resolve({ ok: false, error: `'${host}' is not a hostname` })
      }
      const hit = cache.get(name)
      if (hit !== undefined) {
        if (now() < hit.expires) return Promise.resolve({ ok: true, ips: [...hit.ips] })
        cache.delete(name)
      }
      const pending = inflight.get(name)
      if (pending !== undefined) return pending
      const p = lookupOnce(name).finally(() => inflight.delete(name))
      inflight.set(name, p)
      return p
    },

    recordDerived(name, ips) {
      const host = normaliseHostname(name) ?? name
      // A derived address never outlives the cached resolution that confirmed it.
      const expires = cache.get(host)?.expires ?? now() + ttlMs
      for (const ip of ips) insertBounded(derived, keyOf(ip), { name: host, expires })
    },

    derivedFrom(ip) {
      const key = keyOf(ip)
      const entry = derived.get(key)
      if (entry === undefined) return undefined
      if (now() >= entry.expires) {
        derived.delete(key)
        return undefined
      }
      return entry.name
    },
  }
}
