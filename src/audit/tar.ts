import { promisify } from 'node:util'
import { gunzip, gzip } from 'node:zlib'

/**
 * A minimal, deterministic ustar writer and the matching reader for audit export bundles.
 * Every entry is a regular file with mode 0644, uid/gid 0, empty owner names and the same mtime,
 * so the same entries give byte-identical archives. The reader accepts exactly what the writer
 * produces (regular files and directories; no links, pax or GNU extensions).
 */

const gzipAsync = promisify(gzip)
const gunzipAsync = promisify(gunzip)

/** Default cap on an archive's inflated size (256 MiB). */
export const DEFAULT_MAX_TAR_BYTES = 256 * 1024 * 1024

/** The archive inflates past the caller's cap (a gzip bomb, or simply too big). */
export class TarTooLargeError extends Error {
  readonly maxBytes: number
  constructor(maxBytes: number) {
    super(`archive inflates past the ${maxBytes}-byte cap`)
    this.name = 'TarTooLargeError'
    this.maxBytes = maxBytes
  }
}

const BLOCK = 512
const NAME_LEN = 100
const PREFIX_LEN = 155
const encoder = new TextEncoder()

export interface TarEntry {
  /** Relative, `/`-separated. */
  path: string
  data: Uint8Array
}

function checkPath(path: string): void {
  const ok =
    path.length > 0 &&
    !/[\\\u0000-\u001f\u007f]/.test(path) &&
    !path.startsWith('/') &&
    path.split('/').every((seg) => seg !== '' && seg !== '.' && seg !== '..')
  if (!ok) throw new Error(`unsafe tar path: ${JSON.stringify(path)}`)
}

/** ustar keeps up to 100 bytes in `name` and 155 more in `prefix`, split at a `/`. */
function splitPath(path: string): { name: string; prefix: string } {
  if (encoder.encode(path).byteLength <= NAME_LEN) return { name: path, prefix: '' }
  for (let i = path.indexOf('/'); i !== -1; i = path.indexOf('/', i + 1)) {
    const prefix = path.slice(0, i)
    const name = path.slice(i + 1)
    if (
      encoder.encode(prefix).byteLength <= PREFIX_LEN &&
      encoder.encode(name).byteLength <= NAME_LEN
    ) {
      return { name, prefix }
    }
  }
  throw new Error(`tar path too long: ${path}`)
}

function octal(value: number, width: number): string {
  const digits = value.toString(8)
  if (digits.length > width - 1)
    throw new Error(`value ${value} does not fit a ${width}-byte tar field`)
  return `${digits.padStart(width - 1, '0')}\0`
}

function header(path: string, size: number, mtimeSec: number): Uint8Array {
  const { name, prefix } = splitPath(path)
  const h = Buffer.alloc(BLOCK)
  h.write(name, 0, NAME_LEN, 'utf8')
  h.write(octal(0o644, 8), 100, 'latin1')
  h.write(octal(0, 8), 108, 'latin1') // uid
  h.write(octal(0, 8), 116, 'latin1') // gid
  h.write(octal(size, 12), 124, 'latin1')
  h.write(octal(mtimeSec, 12), 136, 'latin1')
  h.write('        ', 148, 'latin1') // checksum placeholder
  h.write('0', 156, 'latin1') // regular file
  h.write('ustar\u000000', 257, 'latin1')
  h.write(octal(0, 8), 329, 'latin1') // devmajor
  h.write(octal(0, 8), 337, 'latin1') // devminor
  h.write(prefix, 345, PREFIX_LEN, 'utf8')
  h.write(`${octal(checksum(h), 7)} `, 148, 'latin1')
  return h
}

function checksum(h: Uint8Array): number {
  let sum = 0
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : (h[i] as number)
  return sum
}

const padding = (size: number): number => (BLOCK - (size % BLOCK)) % BLOCK

/** Packs `entries` (in the given order) into a gzipped ustar archive; `mtime` for every entry. */
export async function writeTarGz(entries: TarEntry[], mtime: Date): Promise<Uint8Array> {
  const mtimeSec = Math.max(0, Math.floor(mtime.getTime() / 1000))
  const parts: Uint8Array[] = []
  for (const e of entries) {
    checkPath(e.path)
    parts.push(
      header(e.path, e.data.byteLength, mtimeSec),
      e.data,
      new Uint8Array(padding(e.data.byteLength)),
    )
  }
  parts.push(new Uint8Array(BLOCK * 2))
  const gz = await gzipAsync(Buffer.concat(parts), { level: 9 })
  // The gzip header's OS byte depends on the platform zlib was built for; "unknown" everywhere.
  gz[9] = 0xff
  return new Uint8Array(gz.buffer, gz.byteOffset, gz.byteLength)
}

function field(h: Uint8Array, offset: number, length: number): string {
  const bytes = h.subarray(offset, offset + length)
  const end = bytes.indexOf(0)
  return Buffer.from(end === -1 ? bytes : bytes.subarray(0, end)).toString('utf8')
}

function parseOctal(h: Uint8Array, offset: number, length: number): number {
  const text = field(h, offset, length).trim()
  if (!/^[0-7]+$/.test(text)) throw new Error(`bad tar number field at ${offset}`)
  return Number.parseInt(text, 8)
}

/** Unpacks an archive made by `writeTarGz`. Throws on anything malformed or unsupported. */
export async function readTarGz(
  data: Uint8Array,
  opts: {
    /** Inflation stops (with `TarTooLargeError`) past this many bytes; default 256 MiB. */
    maxBytes?: number
  } = {},
): Promise<TarEntry[]> {
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_TAR_BYTES
  let tar: Buffer
  try {
    tar = await gunzipAsync(data, { maxOutputLength: maxBytes })
  } catch (err) {
    if ((err as { code?: unknown } | null)?.code === 'ERR_BUFFER_TOO_LARGE') {
      throw new TarTooLargeError(maxBytes)
    }
    throw new Error(`not a gzip archive: ${err instanceof Error ? err.message : String(err)}`)
  }
  const out: TarEntry[] = []
  let offset = 0
  while (true) {
    if (offset + BLOCK > tar.byteLength) throw new Error('tar archive is truncated')
    const h = tar.subarray(offset, offset + BLOCK)
    if (h.every((b) => b === 0)) break
    if (parseOctal(h, 148, 8) !== checksum(h))
      throw new Error(`bad tar header checksum at ${offset}`)
    if (field(h, 257, 6) !== 'ustar') throw new Error(`not a ustar header at ${offset}`)
    const prefix = field(h, 345, PREFIX_LEN)
    const name = field(h, 0, NAME_LEN)
    const path = prefix === '' ? name : `${prefix}/${name}`
    const size = parseOctal(h, 124, 12)
    const type = String.fromCharCode(h[156] as number)
    offset += BLOCK
    if (offset + size > tar.byteLength) throw new Error(`tar entry ${path} is truncated`)
    if (type === '0' || type === '\0') {
      checkPath(path)
      out.push({ path, data: new Uint8Array(tar.subarray(offset, offset + size)) })
    } else if (type !== '5') {
      throw new Error(`unsupported tar entry type ${JSON.stringify(type)} for ${path}`)
    }
    offset += size + padding(size)
  }
  return out
}
