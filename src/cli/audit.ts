import { mkdir, readFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { parseArgs } from 'node:util'
import { exportAudit } from '../audit/export.js'
import { INDEX_FILE, parseIndex } from '../audit/layout.js'
import { type AuditRecord, AuditRecordSchema } from '../audit/record.js'
import { isNotFound } from '../audit/util.js'
import { verifyAudit } from '../audit/verify.js'
import { resolveOperator } from '../first-run.js'
import { createGuard } from '../guard.js'
import { resolvePaths } from '../paths.js'
import { guardOptions, writeLine } from './args.js'
import type { CliIo } from './main.js'

const USAGE = `Usage: engagement-guard audit <verify|show|export> [options]

  verify  [--case <id>]                 re-walk every chain; one line per file: ok|FAIL <path> <records> <head12>
  show    [--case <id>] [--tail <n>]    the last n records by time (default 20), one line each
  export  [--case <id>] [--out <file>]  a signed tar.gz bundle (default .guard/exports/)`

const short = (hash: string | null): string => (hash === null ? '-' : hash.slice(0, 12))

function parse<T extends Record<string, { type: 'string' }>>(
  args: string[],
  options: T,
): { [K in keyof T]?: string } | undefined {
  try {
    return parseArgs({ args, options, allowPositionals: false, strict: true }).values as {
      [K in keyof T]?: string
    }
  } catch {
    return undefined
  }
}

async function verify(args: string[], io: CliIo): Promise<number> {
  const values = parse(args, { case: { type: 'string' } })
  if (values === undefined) {
    writeLine(io.stderr, USAGE)
    return 1
  }
  const paths = resolvePaths({ env: io.env })
  const dir = join(io.cwd, ...paths.auditDir.split('/'))
  const report = await verifyAudit(dir, values.case === undefined ? {} : { caseId: values.case })
  if (report.files.length === 0) {
    writeLine(io.stdout, `no audit chains under ${dir}`)
    return report.ok ? 0 : 1
  }
  for (const f of report.files) {
    const ok = f.errors.length === 0
    writeLine(io.stdout, `${ok ? 'ok' : 'FAIL'} ${f.path} ${f.records} ${short(f.head)}`)
    for (const e of [...f.errors, ...(f.warnings ?? [])]) {
      writeLine(io.stdout, `  ${e.code} line=${e.line} seq=${e.seq ?? '-'}: ${e.message}`)
    }
  }
  return report.ok ? 0 : 1
}

/** One line per record: seq, time, kind, tool, verdict, reason, first target. */
export function recordLine(r: AuditRecord): string {
  const verdict = r.scope?.verdict ?? r.permission?.kind ?? '-'
  const reason = r.scope?.reason ?? r.permission?.reason ?? '-'
  const target = r.targets[0]?.raw ?? ''
  return `${String(r.seq).padStart(4)} ${r.ts} ${r.kind.padEnd(19)} ${r.tool ?? '-'} ${verdict} ${reason} ${target}`.trimEnd()
}

/**
 * Oldest first by `ts`, then by `seq` (several chains: a hook session, the CLI, a later case
 * session). A timestamp that does not parse is compared as text.
 */
function byTimeThenSeq(a: AuditRecord, b: AuditRecord): number {
  const ta = Date.parse(a.ts)
  const tb = Date.parse(b.ts)
  const d = Number.isNaN(ta) || Number.isNaN(tb) ? a.ts.localeCompare(b.ts) : ta - tb
  return d !== 0 ? d : a.seq - b.seq
}

async function show(args: string[], io: CliIo): Promise<number> {
  const values = parse(args, { case: { type: 'string' }, tail: { type: 'string' } })
  if (values === undefined) {
    writeLine(io.stderr, USAGE)
    return 1
  }
  const tail = values.tail === undefined ? 20 : Number.parseInt(values.tail, 10)
  if (!Number.isInteger(tail) || tail < 1) {
    writeLine(io.stderr, `audit show: --tail must be a positive integer\n${USAGE}`)
    return 1
  }
  const paths = resolvePaths({ env: io.env })
  const dir = join(io.cwd, ...paths.auditDir.split('/'))
  let index: string
  try {
    index = await readFile(join(dir, INDEX_FILE), 'utf8')
  } catch (err) {
    if (!isNotFound(err)) throw err
    writeLine(io.stdout, `no audit log under ${dir}`)
    return 0
  }
  const records: AuditRecord[] = []
  for (const entry of parseIndex(index).entries) {
    if (values.case !== undefined && entry.caseId !== values.case) continue
    let text: string
    try {
      text = await readFile(join(dir, ...entry.file.split('/')), 'utf8')
    } catch (err) {
      if (!isNotFound(err)) throw err
      continue
    }
    for (const line of text.split('\n')) {
      if (line === '') continue
      try {
        const parsed = AuditRecordSchema.safeParse(JSON.parse(line))
        if (parsed.success) records.push(parsed.data)
      } catch {
        // an unreadable line is reported by `verify`, not here
      }
    }
  }
  // Index order would let the chains indexed last hide another session's latest records.
  records.sort(byTimeThenSeq)
  for (const r of records.slice(-tail)) writeLine(io.stdout, recordLine(r))
  return 0
}

async function exportBundle(args: string[], io: CliIo): Promise<number> {
  const values = parse(args, { case: { type: 'string' }, out: { type: 'string' } })
  if (values === undefined) {
    writeLine(io.stderr, USAGE)
    return 1
  }
  const guard = await createGuard(guardOptions(io, { cwd: io.cwd }))
  try {
    const state = guard.cases.state()
    const caseId = values.case ?? ('case' in state ? state.case.engagement.id : undefined)
    if (caseId === undefined) {
      writeLine(io.stderr, 'audit export: no case in this workspace; name one with --case <id>')
      return 1
    }
    let out: string
    if (values.out === undefined) {
      out = join(io.cwd, guard.paths.dirName, 'exports')
      await mkdir(out, { recursive: true })
    } else {
      out = resolve(io.cwd, values.out)
    }
    const result = await exportAudit({
      dir: join(io.cwd, ...guard.paths.auditDir.split('/')),
      caseId,
      out,
      home: guard.paths.home,
      operator: resolveOperator(io.env),
      audit: guard.audit,
      ...(io.now === undefined ? {} : { now: io.now }),
    })
    writeLine(io.stdout, `exported ${result.path} (manifest ${result.manifestSha256.slice(0, 12)})`)
    return 0
  } finally {
    await guard.dispose()
  }
}

/** `engagement-guard audit verify|show|export`. */
export async function runAudit(args: string[], io: CliIo): Promise<number> {
  const [sub, ...rest] = args
  switch (sub) {
    case 'verify':
      return verify(rest, io)
    case 'show':
      return show(rest, io)
    case 'export':
      return exportBundle(rest, io)
    default:
      writeLine(io.stderr, sub === undefined ? USAGE : `unknown audit command '${sub}'\n${USAGE}`)
      return 1
  }
}
