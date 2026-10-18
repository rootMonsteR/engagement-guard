import { createHash } from 'node:crypto'

/** Thrown when a value has no canonical JSON form (undefined, function, symbol, bigint, non-finite number, …). */
export class CanonicalJsonError extends Error {
  constructor(path: string, reason: string) {
    super(`Cannot canonicalise ${path}: ${reason}`)
    this.name = 'CanonicalJsonError'
  }
}

/**
 * Deterministic JSON: object keys sorted by UTF-16 code unit order, arrays in order, no whitespace.
 * Strict where `JSON.stringify` is lossy — anything it would drop, coerce or reject (undefined,
 * functions, symbols, bigint, NaN/±Infinity, cycles) throws, as do non-plain objects (Date, Map, …),
 * so two different inputs never silently hash the same.
 */
export function canonicalJson(value: unknown): string {
  return encode(value, '$', new Set())
}

function encode(value: unknown, path: string, ancestors: Set<object>): string {
  switch (typeof value) {
    case 'string':
    case 'boolean':
      return JSON.stringify(value)
    case 'number':
      if (!Number.isFinite(value)) throw new CanonicalJsonError(path, `${value} is not finite`)
      return JSON.stringify(value)
    case 'object':
      if (value === null) return 'null'
      return encodeObject(value, path, ancestors)
    default:
      throw new CanonicalJsonError(path, `${typeof value} has no JSON form`)
  }
}

function encodeObject(value: object, path: string, ancestors: Set<object>): string {
  if (ancestors.has(value)) throw new CanonicalJsonError(path, 'circular reference')
  ancestors.add(value)
  try {
    if (Array.isArray(value)) {
      const parts: string[] = []
      for (let i = 0; i < value.length; i++) {
        parts.push(encode(value[i], `${path}[${i}]`, ancestors))
      }
      return `[${parts.join(',')}]`
    }
    const proto = Object.getPrototypeOf(value)
    if (proto !== Object.prototype && proto !== null) {
      throw new CanonicalJsonError(
        path,
        `${value.constructor?.name ?? 'object'} is not a plain object`,
      )
    }
    const record = value as Record<string, unknown>
    // Default sort compares UTF-16 code units.
    const keys = Object.keys(record).sort()
    const parts = keys.map(
      (key) => `${JSON.stringify(key)}:${encode(record[key], `${path}.${key}`, ancestors)}`,
    )
    return `{${parts.join(',')}}`
  } finally {
    ancestors.delete(value)
  }
}

/** Lowercase hex SHA-256 of a UTF-8 string or raw bytes. */
export function sha256Hex(s: string | Uint8Array): string {
  return createHash('sha256').update(s).digest('hex')
}
