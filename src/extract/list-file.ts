import { constants } from 'node:fs'
import { open, realpath, stat } from 'node:fs/promises'

/** What the reader needs from a stat result: the file type and its identity. */
export interface ListFileStat {
  isFile(): boolean
  dev: number | bigint
  ino: number | bigint
}

export interface ListFileHandle {
  stat(): Promise<ListFileStat>
  read(
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
  ): Promise<{ bytesRead: number }>
  close(): Promise<void>
}

/** The filesystem calls the reader needs; injectable so the path checks are testable anywhere. */
export interface ListFileFs {
  realpath(path: string): Promise<string>
  stat(path: string): Promise<ListFileStat>
  open(path: string): Promise<ListFileHandle>
}

// Linux pseudo filesystems: process memory/environment, kernel state, devices (`/dev/zero` never ends).
const PSEUDO_FS = /^\/(?:proc|sys|dev)(?:\/|$)/
// Non-blocking (a FIFO swapped in after the path check cannot block the guard) and, where the
// platform has it, O_NOFOLLOW (a symlink swapped in for the resolved path is refused).
const OPEN_FLAGS =
  process.platform === 'win32'
    ? 'r'
    : constants.O_RDONLY | (constants.O_NONBLOCK ?? 0) | (constants.O_NOFOLLOW ?? 0)

export const NODE_LIST_FILE_FS: ListFileFs = {
  realpath: (p) => realpath(p),
  // `bigint: true` so device/inode numbers above 2^53 (seen on Windows) survive the equality check.
  stat: (p) => stat(p, { bigint: true }),
  open: async (p) => {
    const fh = await open(p, OPEN_FLAGS)
    return {
      stat: () => fh.stat({ bigint: true }),
      read: (buffer, offset, length, position) => fh.read(buffer, offset, length, position),
      close: () => fh.close(),
    }
  },
}

/**
 * Reader for `-iL`-style target files: resolves symlinks first and refuses /proc, /sys and /dev,
 * opens the real path (non-blocking, no-follow where supported), refuses anything that is not a
 * regular file according to the open handle, refuses a handle whose device/inode differs from the
 * resolved path's (a symlink race), reads at most `max + 1` bytes and refuses a larger file. The
 * handle is closed on every path.
 */
export function createListFileReader(
  max: number,
  fs: ListFileFs = NODE_LIST_FILE_FS,
): (path: string) => Promise<string> {
  return async (path) => {
    const real = await fs.realpath(path)
    if (PSEUDO_FS.test(real.replaceAll('\\', '/'))) throw new Error(`refusing ${real}`)
    const expected = await fs.stat(real)
    const fh = await fs.open(real)
    try {
      // Re-resolve after opening: a parent-directory symlink swapped between the first resolve and
      // the open could steer `stat`/`open` consistently into a pseudo filesystem (dev/ino would then
      // match), so the pre-open check alone is not enough.
      const rereal = await fs.realpath(path)
      if (PSEUDO_FS.test(rereal.replaceAll('\\', '/'))) throw new Error(`refusing ${rereal}`)
      const actual = await fh.stat()
      if (!actual.isFile()) throw new Error(`not a regular file: ${real}`)
      if (actual.dev !== expected.dev || actual.ino !== expected.ino) {
        throw new Error(`file changed while opening: ${real}`)
      }
      const buf = Buffer.alloc(max + 1)
      let total = 0
      while (total < buf.length) {
        const { bytesRead } = await fh.read(buf, total, buf.length - total, total)
        if (bytesRead === 0) break
        total += bytesRead
      }
      if (total > max) throw new Error(`target file over ${max} bytes`)
      return buf.subarray(0, total).toString('utf8')
    } finally {
      await fh.close()
    }
  }
}
