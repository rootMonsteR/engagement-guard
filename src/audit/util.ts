/** Small internal helpers shared by the audit modules (not exported from the package). */

/** True when `err` is a Node system error with this `code` (`ENOENT`, `EEXIST`, …). */
export const isCode = (err: unknown, code: string): boolean =>
  (err as { code?: unknown } | null)?.code === code

export const isNotFound = (err: unknown): boolean => isCode(err, 'ENOENT')

export const messageOf = (err: unknown): string =>
  err instanceof Error ? err.message : String(err)
