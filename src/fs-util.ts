import { randomBytes } from 'node:crypto'
import { open, rename, rm } from 'node:fs/promises'
import { dirname } from 'node:path'

/** Small file-system helpers for the case lifecycle (not exported from the package). */

/** The path (or a parent of it) does not exist: `ENOENT`, or `ENOTDIR` for a file used as a directory. */
export function isMissing(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code
  return code === 'ENOENT' || code === 'ENOTDIR'
}

/**
 * Writes `text` to a sibling temp file, fsyncs it, then renames it over `path`, so readers see
 * either the old or the new content and a crash cannot leave an empty file behind. On POSIX the
 * directory is fsynced too (best effort) so the rename itself is durable. The temp file is removed
 * on failure.
 */
export async function writeFileAtomic(path: string, text: string, mode = 0o644): Promise<void> {
  const tmp = `${path}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
  try {
    const fh = await open(tmp, 'wx', mode)
    try {
      await fh.writeFile(text, 'utf8')
      // The mode given on create is masked by the umask; set it exactly (POSIX only).
      if (process.platform !== 'win32') await fh.chmod(mode)
      await fh.sync()
    } finally {
      await fh.close()
    }
    await rename(tmp, path)
  } catch (err) {
    await rm(tmp, { force: true })
    throw err
  }
  if (process.platform !== 'win32') await syncDir(dirname(path))
}

async function syncDir(dir: string): Promise<void> {
  try {
    const fh = await open(dir, 'r')
    try {
      await fh.sync()
    } finally {
      await fh.close()
    }
  } catch {
    // Best effort: some file systems refuse fsync on a directory.
  }
}
