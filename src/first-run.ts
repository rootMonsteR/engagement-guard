import { mkdir, readFile } from 'node:fs/promises'
import { hostname, platform, userInfo } from 'node:os'
import { dirname, join } from 'node:path'
import { z } from 'zod'
import { sha256Hex } from './canonical.js'
import { isMissing, writeFileAtomic } from './fs-util.js'
import { STATEMENTS } from './legal/statements.js'
import { OPERATOR_ENV } from './paths.js'

/**
 * First-run acknowledgement and the per-case attestation statement (spec §6.11). The statement
 * texts are `STATEMENTS` (`legal/statements.ts`); changing one means bumping its version, which
 * requires every operator to acknowledge again.
 */

export const FIRST_RUN_STATEMENT_VERSION = 'first-run-v1'
export const ATTESTATION_STATEMENT_VERSION = 'attestation-v1'

export interface LegalStatement {
  version: string
  /** Markdown with `\n` line endings. */
  text: string
  sha256: string
}

export interface FirstRunAck {
  statementVersion: string
  statementSha256: string
  operator: string
  /** ISO-8601 time of the acknowledgement. */
  at: string
  hostFingerprint: string
}

const FirstRunAckSchema = z.strictObject({
  statementVersion: z.string(),
  statementSha256: z.string().regex(/^[0-9a-f]{64}$/),
  operator: z.string().min(1),
  at: z.string(),
  hostFingerprint: z.string(),
})

async function readStatement(version: string): Promise<LegalStatement> {
  const text = STATEMENTS[version]
  if (text === undefined) throw new Error(`unknown legal statement version: ${version}`)
  return { version, text, sha256: sha256Hex(text) }
}

/** The statement every operator acknowledges once per version before any network action. */
export function readFirstRunStatement(): Promise<LegalStatement> {
  return readStatement(FIRST_RUN_STATEMENT_VERSION)
}

/** The statement shown when a case is attested (`engagement-guard engagement freeze` / `edit`). */
export function readAttestationStatement(): Promise<LegalStatement> {
  return readStatement(ATTESTATION_STATEMENT_VERSION)
}

/** `<home>/first-run.json`; `home` is `GuardPaths.home` (`GUARD_HOME` resolved by the caller). */
export function firstRunAckPath(home: string): string {
  return join(home, 'first-run.json')
}

/**
 * The recorded acknowledgement, or `undefined` when there is none, it cannot be read as one, or it
 * was given for another statement version, another text of the current version, or on another
 * host or OS account (a copied file does not carry the acknowledgement).
 */
export async function loadFirstRunAck(home: string): Promise<FirstRunAck | undefined> {
  let text: string
  try {
    text = await readFile(firstRunAckPath(home), 'utf8')
  } catch (err) {
    if (isMissing(err)) return undefined
    throw err
  }
  let parsed: FirstRunAck
  try {
    parsed = FirstRunAckSchema.parse(JSON.parse(text))
  } catch {
    return undefined
  }
  const statement = await readFirstRunStatement()
  if (parsed.statementVersion !== statement.version) return undefined
  if (parsed.statementSha256 !== statement.sha256) return undefined
  if (parsed.hostFingerprint !== hostFingerprint()) return undefined
  return parsed
}

/**
 * Records that `operator` acknowledged the current first-run statement at `now`. The file is
 * written atomically with mode 0600 (POSIX; Windows ignores the mode bits).
 */
export async function recordFirstRunAck(
  home: string,
  operator: string,
  now: Date,
): Promise<FirstRunAck> {
  const name = operator.trim()
  if (name === '') throw new Error('first-run acknowledgement needs an operator name')
  const statement = await readFirstRunStatement()
  const ack: FirstRunAck = {
    statementVersion: statement.version,
    statementSha256: statement.sha256,
    operator: name,
    at: now.toISOString(),
    hostFingerprint: hostFingerprint(),
  }
  const path = firstRunAckPath(home)
  await mkdir(dirname(path), { recursive: true, mode: 0o700 })
  await writeFileAtomic(path, `${JSON.stringify(ack, null, 2)}\n`, 0o600)
  return ack
}

function osUser(): string {
  try {
    return userInfo().username
  } catch {
    // No passwd entry for the uid (some containers).
    return 'unknown'
  }
}

/** A short, stable identifier of this host and OS account: never the raw names. */
export function hostFingerprint(): string {
  return sha256Hex(`${hostname()}|${platform()}|${osUser()}`).slice(0, 16)
}

/** The operator name: `env[name]` (`GUARD_OPERATOR`) when set, else the OS user name. */
export function resolveOperator(env: NodeJS.ProcessEnv, name: string = OPERATOR_ENV): string {
  const fromEnv = env[name]?.trim()
  return fromEnv !== undefined && fromEnv !== '' ? fromEnv : osUser()
}
