import { canonicalJson } from '../canonical.js'

/**
 * A path-based structural diff of two JSON values in canonical form (object keys compared by
 * name, in sorted order; arrays aligned by a longest common subsequence). Each entry carries the
 * JSON values themselves, so an audit record holding the entries is redacted value by value.
 */
export type DiffEntry =
  | { op: 'added'; path: string; value: unknown }
  | { op: 'removed'; path: string; value: unknown }
  | { op: 'changed'; path: string; before: unknown; after: unknown }

/** Above this many LCS cells (middle part of two long, very different lists) the walk degrades to remove-all/add-all. */
const MAX_LCS_CELLS = 1_000_000

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v)

function keyPath(path: string, key: string): string {
  if (/^[A-Za-z_][A-Za-z0-9_-]*$/.test(key)) return path === '' ? key : `${path}.${key}`
  return `${path}[${JSON.stringify(key)}]`
}

/** Every difference between `before` and `after`, in canonical (sorted-key, index) order. */
export function diffValues(before: unknown, after: unknown): DiffEntry[] {
  const out: DiffEntry[] = []
  walk(before, after, '', out)
  return out
}

function walk(a: unknown, b: unknown, path: string, out: DiffEntry[]): void {
  if (isPlainObject(a) && isPlainObject(b)) {
    const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()
    for (const key of keys) {
      const p = keyPath(path, key)
      if (!Object.hasOwn(b, key)) out.push({ op: 'removed', path: p, value: a[key] })
      else if (!Object.hasOwn(a, key)) out.push({ op: 'added', path: p, value: b[key] })
      else walk(a[key], b[key], p, out)
    }
    return
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    diffArrays(a, b, path, out)
    return
  }
  if (canonicalJson(a) !== canonicalJson(b)) out.push({ op: 'changed', path, before: a, after: b })
}

function diffArrays(a: unknown[], b: unknown[], path: string, out: DiffEntry[]): void {
  const ka = a.map((v) => canonicalJson(v))
  const kb = b.map((v) => canonicalJson(v))
  let start = 0
  while (start < a.length && start < b.length && ka[start] === kb[start]) start++
  let endA = a.length
  let endB = b.length
  while (endA > start && endB > start && ka[endA - 1] === kb[endB - 1]) {
    endA--
    endB--
  }
  const n = endA - start
  const m = endB - start
  const removed = (i: number) => out.push({ op: 'removed', path: `${path}[${i}]`, value: a[i] })
  const added = (j: number) => out.push({ op: 'added', path: `${path}[${j}]`, value: b[j] })

  if (n * m > MAX_LCS_CELLS) {
    for (let i = start; i < endA; i++) removed(i)
    for (let j = start; j < endB; j++) added(j)
    return
  }
  // lcs[i * (m + 1) + j] = LCS length of a[start+i..endA) and b[start+j..endB).
  const width = m + 1
  const lcs = new Uint32Array((n + 1) * width)
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i * width + j] =
        ka[start + i] === kb[start + j]
          ? (lcs[(i + 1) * width + j + 1] ?? 0) + 1
          : Math.max(lcs[(i + 1) * width + j] ?? 0, lcs[i * width + j + 1] ?? 0)
    }
  }
  let i = 0
  let j = 0
  while (i < n && j < m) {
    if (ka[start + i] === kb[start + j]) {
      i++
      j++
    } else if ((lcs[(i + 1) * width + j] ?? 0) >= (lcs[i * width + j + 1] ?? 0)) {
      removed(start + i++)
    } else {
      added(start + j++)
    }
  }
  while (i < n) removed(start + i++)
  while (j < m) added(start + j++)
}

/**
 * Renders entries for the operator: the path on its own line, then `- <old>` / `+ <new>` in
 * compact canonical JSON. Consecutive entries on the same path share one path line.
 */
export function renderDiff(entries: readonly DiffEntry[]): string {
  if (entries.length === 0) return '(no changes)'
  const lines: string[] = []
  let last: string | undefined
  for (const e of entries) {
    if (e.path !== last) lines.push(e.path === '' ? '(root)' : e.path)
    last = e.path
    switch (e.op) {
      case 'removed':
        lines.push(`- ${canonicalJson(e.value)}`)
        break
      case 'added':
        lines.push(`+ ${canonicalJson(e.value)}`)
        break
      case 'changed':
        lines.push(`- ${canonicalJson(e.before)}`, `+ ${canonicalJson(e.after)}`)
        break
    }
  }
  return lines.join('\n')
}

/** `renderDiff(diffValues(before, after))`. */
export function scopeDiff(before: unknown, after: unknown): string {
  return renderDiff(diffValues(before, after))
}
