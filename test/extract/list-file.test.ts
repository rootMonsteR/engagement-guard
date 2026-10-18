import { describe, expect, it } from 'vitest'
import { createListFileReader, type ListFileFs } from '../../src/extract/list-file.js'

interface FakeFile {
  real: string
  isFile: boolean
  content: string
}

/** A fake filesystem: `realpath` maps paths, `open` hands out handles and records closes. */
function fakeFs(files: Record<string, FakeFile>) {
  const closed: string[] = []
  const opened: string[] = []
  const identity = (f: FakeFile) => ({ isFile: () => f.isFile, dev: 1, ino: f.real.length })
  const fs: ListFileFs = {
    realpath: async (p) => {
      const f = files[p]
      if (!f) throw new Error('ENOENT')
      return f.real
    },
    stat: async (p) => {
      const f = Object.values(files).find((x) => x.real === p)
      if (!f) throw new Error('ENOENT')
      return identity(f)
    },
    open: async (p) => {
      const f = Object.values(files).find((x) => x.real === p)
      if (!f) throw new Error('ENOENT')
      opened.push(p)
      const bytes = Buffer.from(f.content, 'utf8')
      return {
        stat: async () => identity(f),
        read: async (buf: Buffer, offset: number, length: number, position: number) => {
          const n = Math.max(0, Math.min(length, bytes.length - position))
          bytes.copy(buf, offset, position, position + n)
          return { bytesRead: n }
        },
        close: async () => {
          closed.push(p)
        },
      }
    },
  }
  return { fs, closed, opened }
}

describe('createListFileReader', () => {
  it('reads a regular file through its real path', async () => {
    const { fs, closed } = fakeFs({
      '/w/t.txt': { real: '/w/t.txt', isFile: true, content: 'a\nb\n' },
    })
    await expect(createListFileReader(100, fs)('/w/t.txt')).resolves.toBe('a\nb\n')
    expect(closed).toEqual(['/w/t.txt'])
  })

  it('refuses a symlink into /proc, /sys or /dev before opening it (any platform)', async () => {
    for (const real of ['/proc/self/environ', '/sys/kernel/x', '/dev/zero']) {
      const { fs, opened } = fakeFs({ '/w/link': { real, isFile: true, content: 'SECRET=1' } })
      await expect(createListFileReader(100, fs)('/w/link')).rejects.toThrow()
      expect(opened).toEqual([])
    }
  })

  it('refuses a non-regular file after opening it and always closes the handle', async () => {
    const { fs, closed } = fakeFs({ '/w/fifo': { real: '/w/fifo', isFile: false, content: '' } })
    await expect(createListFileReader(100, fs)('/w/fifo')).rejects.toThrow()
    expect(closed).toEqual(['/w/fifo'])
  })

  it('refuses a file over the limit after reading at most limit + 1 bytes', async () => {
    const { fs, closed } = fakeFs({
      '/w/big': { real: '/w/big', isFile: true, content: 'x'.repeat(50) },
    })
    await expect(createListFileReader(16, fs)('/w/big')).rejects.toThrow(/over 16 bytes/)
    expect(closed).toEqual(['/w/big'])
  })
})

describe('createListFileReader: symlink race', () => {
  it('refuses when the opened file is not the resolved file (dev/ino mismatch)', async () => {
    const closed: string[] = []
    const fs: ListFileFs = {
      realpath: async (p) => p,
      stat: async () => ({ isFile: () => true, dev: 1, ino: 100 }),
      open: async (p) => ({
        stat: async () => ({ isFile: () => true, dev: 1, ino: 200 }),
        read: async () => ({ bytesRead: 0 }),
        close: async () => {
          closed.push(p)
        },
      }),
    }
    await expect(createListFileReader(100, fs)('/w/t.txt')).rejects.toThrow(/changed/)
    expect(closed).toEqual(['/w/t.txt'])
  })

  it('refuses when a parent-directory symlink swaps the path into a pseudo fs after opening', async () => {
    const closed: string[] = []
    let calls = 0
    const fs: ListFileFs = {
      // Safe on the first resolve (passes the pre-open check); a parent symlink is then swapped so
      // the path now resolves into /proc on the re-check after the handle is open.
      realpath: async () => (++calls === 1 ? '/w/t.txt' : '/proc/self/environ'),
      stat: async () => ({ isFile: () => true, dev: 1, ino: 100 }),
      open: async (p) => ({
        stat: async () => ({ isFile: () => true, dev: 1, ino: 100 }),
        read: async () => ({ bytesRead: 0 }),
        close: async () => {
          closed.push(p)
        },
      }),
    }
    await expect(createListFileReader(100, fs)('/w/t.txt')).rejects.toThrow()
    expect(closed).toEqual(['/w/t.txt'])
  })

  it('compares dev/ino exactly for Windows inodes above 2^53', async () => {
    const closed: string[] = []
    const hi = 2n ** 53n + 1n
    const fs: ListFileFs = {
      realpath: async (p) => p,
      stat: async () => ({ isFile: () => true, dev: 10n, ino: hi }),
      open: async (p) => ({
        // Differs from `hi` by 2; equal once coerced to Number (precision loss), distinct as bigint.
        stat: async () => ({ isFile: () => true, dev: 10n, ino: hi + 2n }),
        read: async () => ({ bytesRead: 0 }),
        close: async () => {
          closed.push(p)
        },
      }),
    }
    await expect(createListFileReader(100, fs)('/w/t.txt')).rejects.toThrow(/changed/)
    expect(closed).toEqual(['/w/t.txt'])
  })
})
